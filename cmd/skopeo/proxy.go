package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/containers/image/v5/pkg/blobinfocache"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
)

type proxyOptions struct {
	global *globalOptions
	quiet  bool
	// sockFd is file descriptor for a socketpair()
	sockFd int
	// portNum is a port to use for TCP
	portNum int
}

func proxyCmd(global *globalOptions) *cobra.Command {
	opts := proxyOptions{global: global}
	cmd := &cobra.Command{
		Use:     "proxy [command options]",
		Short:   "Interactive proxy for fetching container images",
		Long:    `Run skopeo as a proxy, supporting HTTP requests to fetch manifests and blobs.`,
		RunE:    commandAction(opts.run),
		Example: `skopeo proxy --sockfd 3`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.IntVar(&opts.sockFd, "sockfd", -1, "Serve on opened socket pair")
	flags.IntVar(&opts.portNum, "port", -1, "Serve on TCP port (localhost)")
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Suppress output information when copying images")
	return cmd
}

type proxyHandler struct {
	transport types.ImageTransport
	cache     types.BlobInfoCache
	sysctx    *types.SystemContext
}

func (h *proxyHandler) implRequest(w http.ResponseWriter, imgname, reqtype, ref string) error {
	ctx := context.TODO()
	imgref, err := h.transport.ParseReference(imgname)
	if err != nil {
		return err
	}
	imgsrc, err := imgref.NewImageSource(ctx, h.sysctx)
	if err != nil {
		return err
	}
	if reqtype == "manifests" {
		rawManifest, _, err := imgsrc.GetManifest(ctx, nil)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rawManifest)))
		r := bytes.NewReader(rawManifest)
		_, err = io.Copy(w, r)
		if err != nil {
			return err
		}
	} else if reqtype == "blobs" {
		d, err := digest.Parse(ref)
		if err != nil {
			return err
		}
		r, blobSize, err := imgsrc.GetBlob(ctx, types.BlobInfo{Digest: d, Size: -1}, h.cache)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", blobSize))
		_, err = io.Copy(w, r)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Unhandled request %s", reqtype)
	}

	return nil
}

// ServeHTTP handles two requests:
//
// GET /<host>/<name>/manifests/<reference>
// GET /<host>/<name>/blobs/<digest>
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path == "" || !strings.HasPrefix(r.URL.Path, "/") {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 {
		w.Header().Set("Content-Length", "0")

		return
	}
	imgref := fmt.Sprintf("//%s/%s/%s", parts[1], parts[2], parts[3])
	reqtype := parts[4]
	ref := parts[5]

	err := h.implRequest(w, imgref, reqtype, ref)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
}

func (opts *proxyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errorShouldDisplayUsage{errors.New("No arguments expected")}
	}
	if opts.sockFd == -1 && opts.portNum == -1 {
		return errorShouldDisplayUsage{errors.New("Expected --sockfd or --port")}
	}
	var err error
	var listener net.Listener
	if opts.sockFd != -1 {
		fdnum, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse datafd %s: %w", args[1], err)
		}
		fd := os.NewFile(uintptr(fdnum), "sock")
		defer fd.Close()

		listener, err = net.FileListener(fd)
		if err != nil {
			return err
		}
	} else {
		addr := net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: opts.portNum,
			Zone: "",
		}
		listener, err = net.ListenTCP("tcp", &addr)
		if err != nil {
			return err
		}
	}
	defer listener.Close()

	sysctx := opts.global.newSystemContext()
	handler := &proxyHandler{
		transport: transports.Get("docker"),
		cache:     blobinfocache.DefaultCache(sysctx),
		sysctx:    sysctx,
	}

	//	ctx, cancel := opts.global.commandTimeoutContext()
	//	defer cancel()

	srv := &http.Server{
		Handler: handler,
	}
	return srv.Serve(listener)
}
