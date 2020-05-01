package blobcertmagic

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/caddyserver/certmagic"
	"github.com/cenkalti/backoff"
)

var (
	lockDuration         = 5 * time.Minute
	fileLockPollInterval = 1 * time.Second
	lockFileExists       = "a lock file already exists"
)

type blobCertStorage struct {
	container azblob.ContainerURL
	Path      string
}

// NewStorage creates a new blob storage based certmagic storage
func NewStorage(path string, container azblob.ContainerURL) certmagic.Storage {
	return &blobCertStorage{
		container: container,
		Path:      path,
	}
}

// Lock acquires the lock for key, blocking until the lock
// can be obtained or an error is returned. Note that, even
// after acquiring a lock, an idempotent operation may have
// already been performed by another process that acquired
// the lock before - so always check to make sure idempotent
// operations still need to be performed after acquiring the
// lock.
//
// The actual implementation of obtaining of a lock must be
// an atomic operation so that multiple Lock calls at the
// same time always results in only one caller receiving the
// lock at any given time.
//
// To prevent deadlocks, all implementations (where this concern
// is relevant) should put a reasonable expiration on the lock in
// case Unlock is unable to be called due to some sort of network
// failure or system crash.
func (bcm *blobCertStorage) Lock(key string) error {
	start := time.Now()
	lockFile := bcm.lockFileName(key)

	for {
		err := bcm.createLockFile(lockFile)
		if err == nil {
			// got the lock, yay
			return nil
		}

		if err.Error() != lockFileExists {
			// unexpected error
			fmt.Println(err)
			return fmt.Errorf("creating lock file: %+v", err)

		}

		// lock file already exists
		info, err := bcm.Stat(lockFile)
		switch {
		case bcm.errNoSuchKey(err):
			// must have just been removed; try again to create it
			continue

		case err != nil:
			// unexpected error
			return fmt.Errorf("accessing lock file: %v", err)

		case bcm.fileLockIsStale(info):
			log.Printf("[INFO][%v] Lock for '%s' is stale; removing then retrying: %s",
				bcm, key, lockFile)
			bcm.deleteLockFile(lockFile)
			continue

		case time.Since(start) > lockDuration*2:
			// should never happen, hopefully
			return fmt.Errorf("possible deadlock: %s passed trying to obtain lock for %s",
				time.Since(start), key)

		default:
			// lockfile exists and is not stale;
			// just wait a moment and try again
			time.Sleep(fileLockPollInterval)

		}
	}
}

// Unlock releases the lock for key. This method must ONLY be
// called after a successful call to Lock, and only after the
// critical section is finished, even if it errored or timed
// out. Unlock cleans up any resources allocated during Lock.
func (bcm *blobCertStorage) Unlock(key string) error {
	lockFile := bcm.lockFileName(key)
	return bcm.deleteLockFile(lockFile)
}

// Store puts value at key.
func (bcm *blobCertStorage) Store(key string, value []byte) error {
	blobURL := bcm.container.NewBlobURL(key)
	_, err := blobURL.ToBlockBlobURL().Upload(context.Background(), bytes.NewReader(value), azblob.BlobHTTPHeaders{}, azblob.Metadata{}, azblob.BlobAccessConditions{})
	return err
}

// Load retrieves the value at key.
func (bcm *blobCertStorage) Load(key string) ([]byte, error) {
	blobURL := bcm.container.NewBlobURL(key)
	res, err := blobURL.ToBlockBlobURL().Download(context.Background(), 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false)
	if err != nil {
		return nil, err
	}

	r := res.Body(azblob.RetryReaderOptions{})
	defer r.Close()

	return ioutil.ReadAll(r)
}

// Delete deletes key. An error should be
// returned only if the key still exists
// when the method returns.
func (bcm *blobCertStorage) Delete(key string) error {
	blobURL := bcm.container.NewBlobURL(key)
	_, err := blobURL.Delete(context.Background(), azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
	if err != nil {
		return err
	}
	return nil
}

// Exists returns true if the key exists
// and there was no error checking.
func (bcm *blobCertStorage) Exists(key string) bool {
	blobURL := bcm.container.NewBlobURL(key)
	_, err := blobURL.GetProperties(context.Background(), azblob.BlobAccessConditions{})
	return err == nil
}

// List returns all keys that match prefix.
// If recursive is true, non-terminal keys
// will be enumerated (i.e. "directories"
// should be walked); otherwise, only keys
// prefixed exactly by prefix will be listed.
func (bcm *blobCertStorage) List(prefix string, recursive bool) ([]string, error) {
	var blobs []azblob.BlobItem

	marker := azblob.Marker{}

	for marker.NotDone() {
		var newBlobs []azblob.BlobItem
		var err error
		newBlobs, marker, err = bcm.listBlobs(prefix, marker)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, newBlobs...)
	}

	var blobNames []string
	for _, blob := range blobs {
		blobNames = append(blobNames, blob.Name)
	}

	return blobNames, nil
}

// Stat returns information about key.
func (bcm *blobCertStorage) Stat(key string) (certmagic.KeyInfo, error) {
	blobURL := bcm.container.NewBlobURL(key)
	ppts, err := blobURL.GetProperties(context.Background(), azblob.BlobAccessConditions{})
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{
		Key:        key,
		Size:       ppts.ContentLength(),
		Modified:   ppts.LastModified(),
		IsTerminal: true,
	}, nil
}

func (bcm *blobCertStorage) lockFileName(key string) string {
	return filepath.Join(bcm.lockDir(), certmagic.StorageKeys.Safe(key)+".lock")
}

func (bcm *blobCertStorage) lockDir() string {
	return filepath.Join(bcm.Path, "locks")
}

func (bcm *blobCertStorage) fileLockIsStale(info certmagic.KeyInfo) bool {
	return time.Since(info.Modified) > lockDuration
}

func (bcm *blobCertStorage) createLockFile(filename string) error {
	exists := bcm.Exists(filename)
	if exists {
		return fmt.Errorf(lockFileExists)
	}

	blobURL := bcm.container.NewBlobURL(filename)
	_, err := blobURL.ToBlockBlobURL().Upload(context.Background(), bytes.NewReader([]byte("lock")), azblob.BlobHTTPHeaders{}, azblob.Metadata{}, azblob.BlobAccessConditions{})

	if err != nil {
		return err
	}
	return nil
}

func (bcm *blobCertStorage) deleteLockFile(filename string) error {
	blobURL := bcm.container.NewBlobURL(filename)
	_, err := blobURL.Delete(context.Background(), azblob.DeleteSnapshotsOptionInclude, azblob.BlobAccessConditions{})
	if err != nil {
		return err
	}
	return nil
}

func (bcm *blobCertStorage) errNoSuchKey(err error) bool {
	if err != nil && strings.Contains(err.Error(), "404") {
		return true
	}
	return false
}

func (bcm *blobCertStorage) listBlobs(prefix string, marker azblob.Marker) ([]azblob.BlobItem, azblob.Marker, error) {
	options := azblob.ListBlobsSegmentOptions{}

	if prefix != "" {
		options.Prefix = prefix
	}

	expoBackOff := backoff.NewExponentialBackOff()
	backOff := backoff.WithMaxRetries(expoBackOff, 5)

	var listResponse *azblob.ListBlobsFlatSegmentResponse
	var err = backoff.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var backoffErr error
		listResponse, backoffErr = bcm.container.ListBlobsFlatSegment(ctx, marker, options)
		return backoffErr
	}, backOff)

	if err != nil {
		return nil, azblob.Marker{}, err
	}

	return listResponse.Segment.BlobItems, listResponse.NextMarker, nil
}
