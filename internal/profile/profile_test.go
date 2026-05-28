package profile

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir, "default")
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	groups := mgr.ListGroups()
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

func TestCreateGroup(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(dir, "default")

	err := mgr.CreateGroup("test-group", "basic")
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	groups := mgr.ListGroups()
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0] != "test-group" {
		t.Errorf("expected test-group, got %s", groups[0])
	}

	// Duplicate should fail
	err = mgr.CreateGroup("test-group", "basic")
	if err == nil {
		t.Error("expected error for duplicate group")
	}
}

func TestAddAndRemoveLink(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(dir, "default")

	link := &Link{
		Remark:   "test-link",
		Protocol: "vmess",
		Address:  "1.2.3.4",
		Port:     443,
	}

	// Add to non-existent group (should auto-create)
	err := mgr.AddLink("default", link)
	if err != nil {
		t.Fatalf("AddLink failed: %v", err)
	}

	// Verify
	g, err := mgr.GetGroup("default")
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if len(g.Links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(g.Links))
	}
	if g.Links[0].Remark != "test-link" {
		t.Errorf("expected test-link, got %s", g.Links[0].Remark)
	}

	// Remove
	err = mgr.RemoveLink("default", "test-link")
	if err != nil {
		t.Fatalf("RemoveLink failed: %v", err)
	}

	g, _ = mgr.GetGroup("default")
	if len(g.Links) != 0 {
		t.Errorf("expected 0 links after remove, got %d", len(g.Links))
	}
}

func TestGetLink(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(dir, "default")

	link := &Link{Remark: "findme", Protocol: "vless", Address: "5.6.7.8", Port: 443}
	mgr.AddLink("default", link)

	found, err := mgr.GetLink("findme")
	if err != nil {
		t.Fatalf("GetLink failed: %v", err)
	}
	if found.Address != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", found.Address)
	}

	// Not found
	_, err = mgr.GetLink("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent link")
	}
}

func TestDeleteGroup(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := NewManager(dir, "default")

	mgr.CreateGroup("to-delete", "basic")
	err := mgr.DeleteGroup("to-delete")
	if err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}

	_, err = mgr.GetGroup("to-delete")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// Create and add data
	mgr1, _ := NewManager(dir, "default")
	mgr1.CreateGroup("persist", "subscription")
	mgr1.AddLink("persist", &Link{Remark: "saved", Protocol: "trojan", Address: "a.b.c", Port: 443})

	// Load fresh manager from same directory
	mgr2, _ := NewManager(dir, "default")
	g, err := mgr2.GetGroup("persist")
	if err != nil {
		t.Fatalf("persistence failed: %v", err)
	}
	if len(g.Links) != 1 {
		t.Errorf("expected 1 persisted link, got %d", len(g.Links))
	}
	if g.Links[0].Remark != "saved" {
		t.Errorf("expected 'saved', got %s", g.Links[0].Remark)
	}
}
