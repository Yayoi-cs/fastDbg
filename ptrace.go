package main

import (
	"fmt"
	"runtime"
)

type anyResp struct {
	v   any
	err error
}

type anyReq struct {
	run  func() (any, error)
	resp chan anyResp
}

type doSysRPC struct {
	req  chan anyReq
	done chan struct{}
}

func doSyscallWorker() *doSysRPC {
	r := &doSysRPC{
		req:  make(chan anyReq),
		done: make(chan struct{}),
	}

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(r.done)

		for q := range r.req {
			var out any
			var err error
			func() {
				defer func() {
					if x := recover(); x != nil {
						err = fmt.Errorf("%v", x)
					}
				}()
				out, err = q.run()
			}()
			q.resp <- anyResp{out, err}
			close(q.resp)
		}
	}()

	return r
}

func (r *doSysRPC) closeSyscall() {
	close(r.req)
	<-r.done
}

func doSyscall[T any](r *doSysRPC, fn func() (T, error)) (T, error) {
	resp := make(chan anyResp, 1)
	r.req <- anyReq{
		run:  func() (any, error) { v, err := fn(); return v, err },
		resp: resp,
	}
	r0 := <-resp
	if r0.err != nil {
		var zero T
		return zero, r0.err
	}
	return r0.v.(T), nil
}

func doSyscallErr(r *doSysRPC, fn func() error) error {
	_, err := doSyscall[struct{}](r, func() (struct{}, error) {
		if err := fn(); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	})
	return err
}
