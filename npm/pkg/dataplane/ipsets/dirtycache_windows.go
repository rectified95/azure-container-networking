package ipsets

type nameOnlyDirtyCache struct {
	toAddOrUpdateCache map[string]struct{}
	toDeleteCache      map[string]struct{}
}

func newDirtyCache() dirtyCacheMaintainer {
	return &nameOnlyDirtyCache{
		toAddOrUpdateCache: make(map[string]struct{}),
		toDeleteCache:      make(map[string]struct{}),
	}
}

func (dc *nameOnlyDirtyCache) reset() {
	dc.toAddOrUpdateCache = make(map[string]struct{})
	dc.toDeleteCache = make(map[string]struct{})
}

func (dc *nameOnlyDirtyCache) create(newSet *IPSet) {
	putIntoAndRemoveFromOther(newSet, dc.toAddOrUpdateCache, dc.toDeleteCache)
}

func (dc *nameOnlyDirtyCache) update(originalSet *IPSet) {
	putIntoAndRemoveFromOther(originalSet, dc.toAddOrUpdateCache, dc.toDeleteCache)
}

func (dc *nameOnlyDirtyCache) delete(originalSet *IPSet) {
	putIntoAndRemoveFromOther(originalSet, dc.toDeleteCache, dc.toAddOrUpdateCache)
}

func putIntoAndRemoveFromOther(set *IPSet, intoCache, fromCache map[string]struct{}) {
	if _, ok := intoCache[set.Name]; ok {
		// NOTE: could throw error if setType is different
		return
	}
	intoCache[set.Name] = struct{}{}
	delete(fromCache, set.Name)
}

func (dc *nameOnlyDirtyCache) getSetsToAddOrUpdate() []string {
	result := make([]string, 0, len(dc.toAddOrUpdateCache))
	for setName := range dc.toAddOrUpdateCache {
		result = append(result, setName)
	}
	return result
}

func (dc *nameOnlyDirtyCache) getSetsToDelete() []string {
	result := make([]string, 0, len(dc.toDeleteCache))
	for setName := range dc.toDeleteCache {
		result = append(result, setName)
	}
	return result
}

func (dc *nameOnlyDirtyCache) numSetsToAddOrUpdate() int {
	return len(dc.toAddOrUpdateCache)
}

func (dc *nameOnlyDirtyCache) numSetsToDelete() int {
	return len(dc.toDeleteCache)
}

func (dc *nameOnlyDirtyCache) isSetToAddOrUpdate(setName string) bool {
	_, ok := dc.toAddOrUpdateCache[setName]
	return ok
}

func (dc *nameOnlyDirtyCache) isSetToDelete(setName string) bool {
	_, ok := dc.toDeleteCache[setName]
	return ok
}

func (dc *nameOnlyDirtyCache) getOriginalMembers(_ string) map[string]struct{} {
	return nil
}
