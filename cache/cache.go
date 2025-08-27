package cache

import (
	"github.com/dgraph-io/ristretto"
	"reflect"
	"time"
	"unsafe"
)

type Cache[K string, V any] interface {
	Set(key K, value V, ttl time.Duration) bool

	Get(key K) (V, bool)

	Del(key K)
}

func NewCache[K string, V any]() (Cache[K, V], error) {
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}
	return &localCache[K, V]{
		cache: cache,
	}, nil
}

type localCache[K string, V any] struct {
	cache *ristretto.Cache
}

func (lc *localCache[K, V]) Set(key K, value V, ttl time.Duration) bool {
	suc := lc.cache.SetWithTTL(key, value, calculateSize(value), ttl)
	lc.cache.Wait()
	return suc
}

func (lc *localCache[K, V]) Get(key K) (V, bool) {
	value, b := lc.cache.Get(key)
	if value == nil {
		var NIL V
		return NIL, false
	}
	return value.(V), b
}

func (lc *localCache[K, V]) Del(key K) {
	lc.cache.Del(key)
}

func calculateSize(v any) int64 {
	rv := reflect.ValueOf(v)

	// 如果是指针，获取指针指向的对象
	if rv.Kind() == reflect.Ptr {
		// 判断指针是否指向有效值，获取其指向对象的大小
		if !rv.IsNil() {
			return int64(unsafe.Sizeof(rv.Elem().Interface()))
		}
		return 0 // 如果指针为空，大小为0
	}

	// 如果不是指针，直接返回对象的大小
	return int64(unsafe.Sizeof(v))
}
