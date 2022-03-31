package ipsets

type memberAwareDirtyCache struct {
	toAddOrUpdateCache map[string]*dirtyInfo
	toDeleteCache      map[string]*dirtyInfo
}

type dirtyInfo struct {
	setType SetType
	members map[string]struct{}
}

func newDirtyCache() dirtyCacheMaintainer {
	return &memberAwareDirtyCache{
		toAddOrUpdateCache: make(map[string]*dirtyInfo),
		toDeleteCache:      make(map[string]*dirtyInfo),
	}
}

func (dc *memberAwareDirtyCache) reset() {
	dc.toAddOrUpdateCache = make(map[string]*dirtyInfo)
	dc.toDeleteCache = make(map[string]*dirtyInfo)
}

func (dc *memberAwareDirtyCache) create(newSet *IPSet) {
	setName := newSet.Name
	if _, ok := dc.toAddOrUpdateCache[setName]; ok {
		// NOTE: could throw error if setType is different
		return
	}
	info, ok := dc.toDeleteCache[setName]
	if !ok {
		info = &dirtyInfo{
			setType: newSet.Type,
			members: make(map[string]struct{}),
		}
	}
	dc.toAddOrUpdateCache[setName] = info
	delete(dc.toDeleteCache, setName)
}

func (dc *memberAwareDirtyCache) update(originalSet *IPSet) {
	putIntoAndRemoveFromOther(originalSet, dc.toAddOrUpdateCache, dc.toDeleteCache)
}

func (dc *memberAwareDirtyCache) delete(originalSet *IPSet) {
	putIntoAndRemoveFromOther(originalSet, dc.toDeleteCache, dc.toAddOrUpdateCache)
}

func putIntoAndRemoveFromOther(originalSet *IPSet, intoCache, fromCache map[string]*dirtyInfo) {
	setName := originalSet.Name
	if _, ok := intoCache[setName]; ok {
		// NOTE: could throw error if setType is different
		return
	}
	info, ok := fromCache[setName]
	if !ok {
		setType := originalSet.Type
		members := make(map[string]struct{})
		if setType.getSetKind() == HashSet {
			for member := range originalSet.IPPodKey {
				members[member] = struct{}{}
			}
		} else {
			for memberName := range originalSet.MemberIPSets {
				members[memberName] = struct{}{}
			}
		}
		info = &dirtyInfo{
			setType: setType,
			members: members,
		}
	}
	intoCache[setName] = info
	delete(fromCache, setName)
}

func (dc *memberAwareDirtyCache) getSetsToAddOrUpdate() []string {
	setsToAddOrUpdate := make([]string, 0, len(dc.toAddOrUpdateCache))
	for setName := range dc.toAddOrUpdateCache {
		setsToAddOrUpdate = append(setsToAddOrUpdate, setName)
	}
	return setsToAddOrUpdate
}

func (dc *memberAwareDirtyCache) getSetsToDelete() []string {
	setsToDelete := make([]string, 0, len(dc.toDeleteCache))
	for setName := range dc.toDeleteCache {
		setsToDelete = append(setsToDelete, setName)
	}
	return setsToDelete
}

func (dc *memberAwareDirtyCache) numSetsToAddOrUpdate() int {
	return len(dc.toAddOrUpdateCache)
}

func (dc *memberAwareDirtyCache) numSetsToDelete() int {
	return len(dc.toDeleteCache)
}

func (dc *memberAwareDirtyCache) isSetToAddOrUpdate(setName string) bool {
	_, ok := dc.toAddOrUpdateCache[setName]
	return ok
}

func (dc *memberAwareDirtyCache) isSetToDelete(setName string) bool {
	_, ok := dc.toDeleteCache[setName]
	return ok
}

func (dc *memberAwareDirtyCache) getOriginalMembers(setName string) map[string]struct{} {
	info, ok := dc.toAddOrUpdateCache[setName]
	if !ok {
		return nil
	}
	members := make(map[string]struct{}, len(info.members))
	for member := range info.members {
		members[member] = struct{}{}
	}
	return members
}
