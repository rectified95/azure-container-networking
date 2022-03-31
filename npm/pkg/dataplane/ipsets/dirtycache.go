package ipsets

// dirtyCacheMaintainer will maintain the dirty cache
type dirtyCacheMaintainer interface {
	// reset empties dirty cache
	reset()
	// create will mark the new set to be created.
	create(newSet *IPSet)
	// update will mark the set to be updated and may note the original members of the set.
	update(originalSet *IPSet)
	// delete will mark the set to be deleted in the cache
	delete(originalSet *IPSet)
	// getSetsToAddOrUpdate returns the list of set names to be added or updated
	getSetsToAddOrUpdate() []string
	// getSetsToDelete returns the list of set names to be deleted
	getSetsToDelete() []string
	// numSetsToAddOrUpdate returns the number of sets to be added or updated
	numSetsToAddOrUpdate() int
	// numSetsToDelete returns the number of sets to be deleted
	numSetsToDelete() int
	// isSetToAddOrUpdate returns true if the set is dirty and should be added or updated
	isSetToAddOrUpdate(setName string) bool
	// isSetToDelete returns true if the set is dirty and should be deleted
	isSetToDelete(setName string) bool
	// getOriginalMembers returns the original members of the set before it was dirty
	// members are either IPs, CIDRs, IP-Port pairs, or set names if the parent is a list
	getOriginalMembers(setName string) map[string]struct{}
}
