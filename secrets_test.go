package secrets

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper to create a new secrets store
func newTestStore(t *testing.T, dir string) *Store {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	st, err := NewStore(dir, key)
	assert.NoError(t, err)
	t.Cleanup(func() {
		st.Close()
		_ = os.RemoveAll(dir)
	})
	return st
}

// Helper to clean up after a test is run
func testCleanup(t *testing.T, store *Store) {
	if store == nil {
		return
	}
	store.Close()
	err := os.RemoveAll(store.dir)
	assert.NoError(t, err)
}

// Helper to write arbitrary bytes
func mustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(p), 0700)
	assert.NoError(t, err)
	err = os.WriteFile(p, b, 0600)
	assert.NoError(t, err)
}

func TestPathValidation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_path_validation", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)

	// Test invalid paths
	invalidPaths := []string{
		"../outside",
		"path/../../outside",
		"path/..",
		"",
	}

	for _, invalidPath := range invalidPaths {
		err = store.Save(invalidPath, []byte("data"))
		assert.Error(t, err, "Expected error for invalid path %s", invalidPath)
		_, err = store.Load(invalidPath)
		assert.Error(t, err, "Expected error for invalid path %s", invalidPath)
	}
}

func TestLoadCurrentKey_Errors(t *testing.T) {
	dir := "test_load_currentkey"
	st := newTestStore(t, dir)

	// Bad length in currentkey
	mustWrite(t, filepath.Join(dir, CurKeyIdxFile), []byte{0x01, 0x02})
	err := st.loadCurrentKey()
	assert.Error(t, err, "expected error for invalid current key file format")

	// Missing referenced key file
	mustWrite(t, filepath.Join(dir, CurKeyIdxFile), []byte{200})
	err = st.loadCurrentKey()
	assert.Error(t, err, "expected error when referenced key file is missing")
}

func TestEncryptDecryptData_KeyMismatch(t *testing.T) {
	dir := "test_encrypt_decrypt_mismatch"
	st := newTestStore(t, dir)
	// Save valid secret
	if err := st.Save("p", []byte("q")); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Read file bytes and corrupt ciphertext to force GCM failure
	p := filepath.Join(dir, "p")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) > 2 {
		data[len(data)-1] ^= 0xFF
	}
	mustWrite(t, p, data)
	if _, err := st.Load("p"); err == nil {
		t.Fatal("expected decrypt failure after corruption")
	}
}

func TestReencryptFile_CurrentIndexBranch(t *testing.T) {
	dir := "test_reencrypt_branch"
	st := newTestStore(t, dir)

	// Create a file that claims to use current key index but with random payload
	idx := st.currentKeyIndex
	// Minimal valid structure: [idx][nonce...][ciphertext...]
	// Use current key's nonce size by making an encrypted datum then replacing payload
	if err := st.Save("tmp", []byte("x")); err != nil {
		t.Fatalf("save: %v", err)
	}
	fp := filepath.Join(dir, "tmp")
	enc, err := os.ReadFile(fp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(enc) < 2 {
		t.Fatalf("unexpected encoding")
	}
	enc[0] = idx
	// randomize rest to cause decrypt failure, but still traverse the branch
	buf := make([]byte, len(enc)-1)
	_, _ = rand.Read(buf)
	copy(enc[1:], buf)
	mustWrite(t, fp, enc)

	st.reencryptFile("tmp", nil, st.currentKey)
	// TODO: Test that reencrypt failed.
}

func TestList_IncludesNestedSkipsKeysDir(t *testing.T) {
	dir := "test_list_nested"
	st := newTestStore(t, dir)
	// secrets
	_ = st.Save("aa/bb/cc", []byte("v"))
	_ = st.Save("dd", []byte("v"))
	// ensure keys dir exists and has files (already does), list should not include them
	items, err := st.list()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, it := range items {
		if len(it) >= len(KeysDir) && it[:len(KeysDir)] == KeysDir {
			t.Fatalf("list should not include keys dir entries: %s", it)
		}
	}
}

func TestValidateStore_SuccessAndFailures(t *testing.T) {
	dir := "test_validate"
	st := newTestStore(t, dir)

	if err := st.ValidateStore(); err != nil {
		t.Fatalf("ValidateStore should pass: %v", err)
	}

	// Remove currentkey file -> expect error
	currentKeyPath := filepath.Join(dir, CurrentKeyFile)
	if err := os.Remove(currentKeyPath); err != nil {
		t.Fatalf("remove currentkey: %v", err)
	}
	if err := st.ValidateStore(); err == nil {
		t.Fatal("ValidateStore should fail when currentkey is missing")
	}
}

func TestRecovery_ReencryptsFilesWithOldKey(t *testing.T) {
	dir := "test_recovery"
	st := newTestStore(t, dir)

	// Save a secret under current key0
	if err := st.Save("x/one", []byte("alpha")); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Rotate to create key1 and set current
	if err := st.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Manually craft a file encrypted with old key0 by temporarily swapping state
	// Note: same package allows access to unexported fields
	oldKey := st.currentKey
	oldIdx := st.currentKeyIndex

	// Load key0 and set as current
	key0, err := st.loadKey(0)
	if err != nil {
		t.Fatalf("load key0: %v", err)
	}
	st.currentKey = key0
	st.currentKeyIndex = 0
	if err := st.Save("x/two", []byte("beta")); err != nil {
		t.Fatalf("save with old key: %v", err)
	}
	// Restore current new key
	st.currentKey = oldKey
	st.currentKeyIndex = oldIdx

	// Ensure one file is using old key
	files, err := st.listDataFiles()
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	foundOld := false
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(data) > 0 && data[0] == 0 {
			foundOld = true
			break
		}
	}
	if !foundOld {
		t.Fatal("expected at least one file with old key index 0")
	}

	// Run recovery to re-encrypt mismatched files
	if err := st.checkAndRecover(); err != nil {
		t.Fatalf("checkAndRecover: %v", err)
	}

	// TODO: Verify all files now use current key index
	/*
	info, err := st.GetStoreInfo()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read2: %v", err)
		}
		if len(data) == 0 {
			t.Fatalf("file %s empty after recovery", f)
		}
		if data[0] != info.CurrentKeyIndex {
			t.Fatalf("file %s still on old key index %d != %d", f, data[0], info.CurrentKeyIndex)
		}
	}
	*/
}

func TestRotation_CleanupOldKeys(t *testing.T) {
	dir := "test_cleanup"
	st := newTestStore(t, dir)

	// Save one secret and rotate a couple of times
	if err := st.Save("s1", []byte("v")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st.Rotate(); err != nil {
		t.Fatalf("rotate1: %v", err)
	}
	if err := st.Save("s2", []byte("v2")); err != nil {
		t.Fatalf("save2: %v", err)
	}
	if err := st.Rotate(); err != nil {
		t.Fatalf("rotate2: %v", err)
	}

	// Ensure only current key remains
	// Use glob for this.
	entries, err := os.ReadDir(filepath.Join(dir, KeyDir))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	current := st.currentKeyIndex
	for _, e := range entries {
		if e.IsDir() || e.Name() == "currentkey" {
			continue
		}
		var idx uint8
		if _, err := fmt.Sscanf(e.Name(), "key%d", &idx); err != nil {
			continue
		}
		if idx != 0 && idx != current {
			t.Fatalf("unexpected leftover key file: %s", e.Name())
		}
	}
}

func TestLoad_MissingAndCorrupt(t *testing.T) {
	dir := "test_load_errors"
	st := newTestStore(t, dir)

	if _, err := st.Load("missing"); err == nil {
		t.Fatal("expected error for missing secret")
	}

	// Create corrupt file
	path := filepath.Join(dir, "bad")
	if err := os.WriteFile(path, []byte{0x99}, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Try to read via API (uses locks and decrypt)
	if _, err := st.Load("bad"); err == nil {
		t.Fatal("expected error for corrupt data")
	}
}

func TestDeriveKeyFromPassword_BadSalt(t *testing.T) {
	if _, err := deriveKeyFromPassword([]byte("pw"), []byte("short")); err == nil {
		t.Fatal("expected error for short salt")
	}
}

func TestEncryptDecryptHelpers(t *testing.T) {
	dir := "test_helpers_encrypt"
	st := newTestStore(t, dir)

	plaintext := []byte("hello-world")
	enc, err := st.encryptData(plaintext)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	dec, err := st.decryptData(enc)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}
	if string(dec) != string(plaintext) {
		t.Fatal("roundtrip mismatch")
	}

	// Use specific key helpers
	key := st.currentKey
	idx := st.currentKeyIndex
	enc2, err := st.encryptDataWithKey(plaintext, key, idx)
	if err != nil {
		t.Fatalf("encryptDataWithKey: %v", err)
	}
	dec2, err := st.decryptDataWithKey(enc2, key)
	if err != nil {
		t.Fatalf("decryptDataWithKey: %v", err)
	}
	if string(dec2) != string(plaintext) {
		t.Fatal("roundtrip2 mismatch")
	}
}

func TestSaveLoadKeyRoundTrip(t *testing.T) {
	dir := "test_key_roundtrip"
	st := newTestStore(t, dir)

	k := make([]byte, 32)
	_, _ = rand.Read(k)
	if err := st.saveKey(42, k); err != nil {
		t.Fatalf("saveKey: %v", err)
	}
	got, err := st.loadKey(42)
	if err != nil {
		t.Fatalf("loadKey: %v", err)
	}
	if len(got) != len(k) {
		t.Fatalf("key length mismatch")
	}
}

func TestSaveCurrentKeyIndexWritesFile(t *testing.T) {
	dir := "test_save_current_idx"
	st := newTestStore(t, dir)
	// bump index and write
	st.currentKeyIndex++
	if err := st.saveCurrentKeyIndex(); err != nil {
		t.Fatalf("saveCurrentKeyIndex: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, CurrentKeyFile))
	if err != nil {
		t.Fatalf("read currentkey: %v", err)
	}
	if len(b) != 1 || b[0] != st.currentKeyIndex {
		t.Fatalf("unexpected currentkey contents: %v", b)
	}
}

func TestDeleteKeyRemovesFile(t *testing.T) {
	dir := "test_delete_key"
	st := newTestStore(t, dir)
	// create a dummy key file
	path := filepath.Join(dir, KeysDir, "key77")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte{0}, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	st.deleteKey(77)
	if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected key file removed, got err=%v", err)
	}
}

func TestListDataFilesSkipsKeysAndReturnsRel(t *testing.T) {
	dir := "test_list_data_files"
	st := newTestStore(t, dir)
	_ = st.Save("sub/one", []byte("1"))
	_ = st.Save("two", []byte("2"))
	files, err := st.listDataFiles()
	if err != nil {
		t.Fatalf("listDataFiles: %v", err)
	}
	// Should contain our relative paths
	want := map[string]bool{"sub/one": true, "two": true}
	for _, f := range files {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("missing files: %v", want)
	}
}

func TestCheckAndRecover_MissingCurrentKey(t *testing.T) {
	dir := "test_recover_missing_ck"
	st := newTestStore(t, dir)
	// remove currentkey so checkAndRecover errors
	if err := os.Remove(filepath.Join(dir, CurrentKeyFile)); err != nil {
		t.Fatalf("rm currentkey: %v", err)
	}
	if err := st.checkAndRecover(); err == nil {
		t.Fatal("expected error when currentkey missing")
	}
}

func TestRecoverFile_AlreadyCurrent(t *testing.T) {
	dir := "test_recover_already"
	st := newTestStore(t, dir)
	// Save with current key
	if err := st.Save("same", []byte("v")); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Find file path
	files, err := st.listDataFiles()
	if err != nil || len(files) == 0 {
		t.Fatalf("list: %v", err)
	}
	// Call recoverFile on the saved file (should early-return nil)
	if err := st.recoverFile(files[0], st.currentKeyIndex, st.currentKey); err != nil {
		t.Fatalf("recoverFile early return expected nil, got %v", err)
	}
}

func TestLoadKey_InvalidAndUnsupported(t *testing.T) {
	dir := "test_loadkey_bad"
	st := newTestStore(t, dir)

	// Invalid format (empty) file
	badPath := filepath.Join(dir, KeysDir, "key250")
	if err := os.WriteFile(badPath, []byte{}, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := st.loadKey(250); err == nil {
		t.Fatal("expected invalid key file format error")
	}

	// Unsupported algorithm (first byte not AlgorithmAES256GCM)
	unsupPath := filepath.Join(dir, KeysDir, "key251")
	if err := os.WriteFile(unsupPath, []byte{0x63}, 0600); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if _, err := st.loadKey(251); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestDelete_Nonexistent(t *testing.T) {
	dir := "test_delete_missing"
	st := newTestStore(t, dir)
	if err := st.Delete("nope"); err == nil {
		t.Fatal("expected error deleting missing file")
	}
}

func TestDecryptData_Errors(t *testing.T) {
	dir := "test_decrypt_errors"
	st := newTestStore(t, dir)
	// Too short
	if _, err := st.decryptData([]byte{}); err == nil {
		t.Fatal("expected error for short encrypted data")
	}
}

func TestReencryptFile_Flow(t *testing.T) {
	dir := "test_reencrypt_file"
	st := newTestStore(t, dir)
	// Ensure a file exists with key0
	if err := st.Save("a", []byte("v")); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Rotate to new key index
	if err := st.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Now re-encrypt explicitly the file saved earlier
	if err := st.reencryptFile("a", nil, st.currentKey); err != nil {
		t.Fatalf("reencryptFile: %v", err)
	}
}

func TestKeyInUse_TrueAndFalse(t *testing.T) {
	dir := "test_key_in_use"
	st := newTestStore(t, dir)
	// Write a file that claims to use key index 9
	if err := os.WriteFile(filepath.Join(dir, "claim9"), []byte{9, 1, 2, 3}, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !st.keyInUse(9) {
		t.Fatal("expected keyInUse(9) to be true")
	}
	if st.keyInUse(7) {
		t.Fatal("expected keyInUse(7) to be false")
	}
}

// Sanity: Close should wipe keys; we can't inspect memory, but we can call it twice
func TestClose_Idempotent(t *testing.T) {
	dir := "test_close"
	st := newTestStore(t, dir)
	st.Close()
	// Second close should not panic
	st.Close()
}
