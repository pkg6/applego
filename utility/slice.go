package utility

import "sort"

type NumberComparable interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64 |
		~string
}

func Max[T NumberComparable](numbers []T) T {
	var max T
	for _, v := range numbers {
		if v > max {
			max = v
		}
	}
	return max
}

func Min[T NumberComparable](numbers []T) T {
	var min T
	for _, v := range numbers {
		if v < min {
			min = v
		}
	}
	return min
}

func OrderBy[T comparable, N NumberComparable](s []T, nFn func(t T) N, order int) []T {
	var ret []T
	maps := map[N]T{}
	var ns []N
	for _, t := range s {
		fni := nFn(t)
		maps[fni] = t
		ns = append(ns, fni)
	}
	sort.Slice(ns, func(i, j int) bool {
		if order > 0 {
			return ns[i] > ns[j]
		} else {
			return ns[i] < ns[j]
		}
	})
	for _, td := range ns {
		ret = append(ret, maps[td])
	}
	return ret
}
