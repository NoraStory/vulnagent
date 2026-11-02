package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"runtime"
	"sync"
)

// parallelGzipChunk 每个压缩分块大小；分块压缩后按顺序拼接为多个 gzip member。
const parallelGzipChunk = 4 << 20

type gzipJob struct {
	index int
	data  []byte
}

type gzipResult struct {
	index int
	data  []byte
	err   error
}

// compressFileParallel 多协程压缩文件，输出由多个 gzip member 顺序拼接而成，
// 标准 gzip 解压器可直接读取。workers<=0 时按 CPU 核数（最多 8）自动选择。
func compressFileParallel(src, dst string, workers int) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	output, err := os.Create(dst)
	if err != nil {
		_ = input.Close()
		return err
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
		if workers < 1 {
			workers = 1
		}
	}

	jobs := make(chan gzipJob, workers)
	results := make(chan gzipResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				var buf bytes.Buffer
				writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
				if err == nil {
					if _, writeErr := writer.Write(job.data); writeErr != nil {
						err = writeErr
					}
					if closeErr := writer.Close(); err == nil {
						err = closeErr
					}
				}
				results <- gzipResult{index: job.index, data: buf.Bytes(), err: err}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, parallelGzipChunk)
		index := 0
		for {
			n, err := input.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				jobs <- gzipJob{index: index, data: chunk}
				index++
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				close(jobs)
				readErr <- err
				return
			}
		}
		close(jobs)
		readErr <- nil
	}()

	var (
		writeErr error
		chunks   int
		next     int
		pending  = make(map[int][]byte)
	)
	for result := range results {
		if result.err != nil && writeErr == nil {
			writeErr = result.err
		}
		chunks++
		pending[result.index] = result.data
		for {
			data, ok := pending[next]
			if !ok {
				break
			}
			if writeErr == nil {
				if _, err := output.Write(data); err != nil {
					writeErr = err
				}
			}
			delete(pending, next)
			next++
		}
	}
	if err := <-readErr; err != nil && writeErr == nil {
		writeErr = err
	}
	if chunks == 0 && writeErr == nil {
		// 空文件也要输出合法的 gzip member
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(nil); err != nil {
			writeErr = err
		}
		if err := writer.Close(); err != nil && writeErr == nil {
			writeErr = err
		}
		if _, err := output.Write(buf.Bytes()); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	if err := output.Close(); err != nil && writeErr == nil {
		writeErr = err
	}
	if err := input.Close(); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		_ = os.Remove(dst)
	}
	return writeErr
}
