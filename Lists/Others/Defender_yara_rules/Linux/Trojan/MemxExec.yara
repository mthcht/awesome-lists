rule Trojan_Linux_MemxExec_A_2147917353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MemxExec.A!MTB"
        threat_id = "2147917353"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MemxExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/memx/main.go" ascii //weight: 1
        $x_1_2 = "encoding/hex/hex.go" ascii //weight: 1
        $x_1_3 = "syscall/syscall_linux_amd64.go" ascii //weight: 1
        $x_1_4 = "src/os/exec.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

