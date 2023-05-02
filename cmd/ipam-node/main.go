/*
 Copyright 2023, NVIDIA CORPORATION & AFFILIATES
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package main

import (
    "context"
    "fmt"
    "os"
    "net"
    "path/filepath"
    "strconv"
    "strings"    
    "os/signal"
    "syscall"
 //   "strconv"

    "github.com/spf13/cobra"
    "github.com/jaypipes/ghw"

 //   v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    coreclientset "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/tools/clientcmd"
)

const (
    KubeApiQps   = 5
    KubeApiBurst = 10
)


type Clientset struct {
    core coreclientset.Interface
}

type Config struct {
    clientset *Clientset
}

// NewCommand creates a *cobra.Command object with default parameters.
func NewCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:  "nvidia-static-ipamd",
        Long: "nvidia-static-ipamd implements static ipam file creation.",
    }

    cmd.RunE = func(cmd *cobra.Command, args []string) error {
        csconfig, err := GetClientsetConfig()
        if err != nil {
            return fmt.Errorf("create client configuration: %v", err)
        }

        coreclient, err := coreclientset.NewForConfig(csconfig)
        if err != nil {
            return fmt.Errorf("create core client: %v", err)
        }
        config := &Config{
            clientset: &Clientset{
                coreclient,
            },
        }

        return StartIpam(config)
    }

    return cmd
}

func GetClientsetConfig() (*rest.Config, error) {
    var csconfig *rest.Config
    kubeconfig := os.Getenv("KUBECONFIG")

    var err error
    if kubeconfig == "" {
        csconfig, err = rest.InClusterConfig()
        if err != nil {
            return nil, fmt.Errorf("create in-cluster client configuration: %v", err)
        }
    } else {
        csconfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
        if err != nil {
            return nil, fmt.Errorf("create out-of-cluster client configuration: %v", err)
        }
    }

    csconfig.QPS = KubeApiQps
    csconfig.Burst = KubeApiBurst

    return csconfig, nil
}

func StartIpam(config *Config) error {

    nodeName := os.Getenv("NODE_NAME")
    ipam :=  &ipam {
        clientset: config.clientset,
        nodeName : nodeName,
    }
    go ipam.start()
    sigc := make(chan os.Signal, 1)
    signal.Notify(sigc, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
    <-sigc
    ipam.stop()
    return nil
}

type ipam struct {
    clientset *Clientset
    nodeName string
    startIp net.IP
    endIP net.IP
    gateway net.IP
    mask string
    interfaceRegEx string
    maxVFsPerPF int
}

type mlnxNic struct {
    isDualPort bool
    TotalVfs    int
}


type staticEntry struct {
    ip string
    gw string
}



func (i *ipam) start() {
    node, err := i.clientset.core.CoreV1().Nodes().Get(context.TODO(), i.nodeName, metav1.GetOptions{})
    if err != nil {
       fmt.Printf("start(): failed: %v", err) 
    }
    fmt.Printf("node %+v", node)
    //i.parseNodeStaticAnnotation(node)
    i.maxVFsPerPF = 16
    i.gateway = net.ParseIP("1.1.1.1")
    i.startIp = net.ParseIP("1.1.1.2")
    i.mask = "/16"
    i.discoverHostDevices()
}

/*
func (i *ipam) parseNodeStaticAnnotation(node *v1.Node) {
     ipBlock, _ := node.Annotations["static-ipam.nvidia.com/ip-block"]
     i.startIp = net.ParseIP(ipBlock["startIP"])
     i.endIP = net.ParseIP(ipBlock["endIP"])
     i.gateway = net.ParseIP(ipBlock["gateway"])
     i.interfaceRegEx = ipBlock["interfaceRegEx"]
     i.maxVFsPerPF = strconv.Atoi(ipBlock["maxVFsPerPF"])
}
*/

func (i *ipam) stop(){

}

func getPciAddressPrefix(pciAddress string) string {
    return pciAddress[:len(pciAddress)-1]
}

func isDualPort(pciAddress string) bool {
    return pciAddress[len(pciAddress)-1:] == "1"
}


func generateBDF(pciAddress string, offset int) string{
    new_function := offset % 8
    new_slot := offset / 8
    var domain, bus, slot, fn int
    _, _ = fmt.Sscanf(pciAddress, "%04x:%02x:%02x.%d", &domain, &bus, &slot, &fn)    
    return fmt.Sprintf("%04x:%02x:%02x.%d", domain, bus, new_slot, new_function)
}

func nextIP(ip net.IP, inc uint) net.IP {
    i := ip.To4()  
    v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
    v += inc
    v3 := byte(v & 0xFF)
    v2 := byte((v >> 8) & 0xFF)
    v1 := byte((v >> 16) & 0xFF)
    v0 := byte((v >> 24) & 0xFF)
    return net.IPv4(v0, v1, v2, v3)
}

func (i *ipam) discoverHostDevices() error {
    pci, err := ghw.PCI()
    if err != nil {
        return fmt.Errorf("discoverDevices(): error getting PCI info: %v", err)
    }

    devices := pci.ListDevices()
    if len(devices) == 0 {
        fmt.Println("discoverDevices(): no PCI network device found")
    }

    pfNics := make(map[string]mlnxNic)

    for _, device := range devices {
        if device.Vendor.ID != "15b3"{
            continue
        }
        fmt.Printf("vendor %+v\n", device.Vendor.ID)
        fmt.Printf("device PCI Address %+v\n", device.Address)
        devPath := filepath.Join("/sys/bus/pci/devices", device.Address)
        buf, err := os.ReadFile(filepath.Join(devPath, "sriov_totalvfs"))
        if err != nil {
            // is not a physfn. Since we will fill virtfn from physfn, we can give up now
            continue
        }
        totalVfs, err := strconv.Atoi(strings.TrimSpace(string(buf)))
        fmt.Printf("sriov_totalvfs %d\n", totalVfs)
        fmt.Printf("getPciAddressPrefix %s\n", getPciAddressPrefix(device.Address))
        fmt.Printf("isDualPort %t\n", isDualPort(device.Address))
        _, exist := pfNics[getPciAddressPrefix(device.Address)]
        if !exist {
            pfNics[getPciAddressPrefix(device.Address)] = mlnxNic{isDualPort: false, TotalVfs: totalVfs}
        } else {
            pfNics[getPciAddressPrefix(device.Address)] = mlnxNic{isDualPort: true, TotalVfs: totalVfs}
        }
    }

    fmt.Printf("pfNics: %+v\n", pfNics)

    staticConfig := make(map[string]staticEntry)

    fmt.Println(nextIP(net.ParseIP("1.0.0.255"), 1))
    ipAddr := i.startIp 
    for pciAddressPrefix, pfNic := range pfNics {
        
        if pfNic.isDualPort {
            offset := 2
            for  vfIndex := 0; vfIndex < i.maxVFsPerPF; vfIndex++ {
               vfAddress := generateBDF(pciAddressPrefix +"0",   vfIndex + offset)
               staticConfig[vfAddress] = staticEntry{ ip: ipAddr.String() + i.mask, gw: i.gateway.String()}
               ipAddr = nextIP(ipAddr, 1)
            }
            for  vfIndex := 0; vfIndex < i.maxVFsPerPF; vfIndex++ {
               vfAddress := generateBDF(pciAddressPrefix +"1",   vfIndex + offset + pfNic.TotalVfs)
               staticConfig[vfAddress] = staticEntry{ ip: ipAddr.String() + i.mask, gw: i.gateway.String()}
               ipAddr = nextIP(ipAddr, 1)
            }   
        } else {
            offset := 1
            for  vfIndex := 0; vfIndex < i.maxVFsPerPF; vfIndex++ {
               vfAddress := generateBDF(pciAddressPrefix +"0",   vfIndex + offset)
               staticConfig[vfAddress] = staticEntry{ ip: ipAddr.String() + i.mask, gw: i.gateway.String()}
               ipAddr = nextIP(ipAddr, 1)
            }           
        }
    }

    fmt.Printf("staticConfig: %+v\n", staticConfig)

    return nil
}

func main() {
    command := NewCommand()
    err := command.Execute()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    }
}