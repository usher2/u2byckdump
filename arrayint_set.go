package main

type ArrayIntSet []uint64

func (a ArrayIntSet) Blank() bool { return len(a) == 0 }

func (a ArrayIntSet) Add(v uint64) ArrayIntSet {
	for i := range a {
		if a[i] == v {
			return a
		}
	}
	return append(a, v)
}

func (a ArrayIntSet) Del(v uint64) ArrayIntSet {
	idx := -1
	for i := range a {
		if a[i] == v {
			idx = i
			break
		}
	}
	if idx == -1 {
		return a
	}
	return append(a[:idx], a[idx+1:]...)
}
