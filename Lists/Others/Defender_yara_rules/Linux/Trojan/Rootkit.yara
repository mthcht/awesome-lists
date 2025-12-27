rule Trojan_Linux_Rootkit_B_2147918995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Rootkit.B!MTB"
        threat_id = "2147918995"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "root-shell" ascii //weight: 1
        $x_1_2 = "unhide-pid" ascii //weight: 1
        $x_1_3 = "rootkit LKM" ascii //weight: 1
        $x_1_4 = "hide-file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Rootkit_C_2147956180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Rootkit.C!MTB"
        threat_id = "2147956180"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/amitschendel/curing/pkg/server.handleRequest" ascii //weight: 1
        $x_1_2 = "/curing/pkg/server.NewServer" ascii //weight: 1
        $x_1_3 = "/curing/pkg/config.LoadConfig" ascii //weight: 1
        $x_1_4 = "/root/curing/pkg/server/server.go" ascii //weight: 1
        $x_1_5 = "/root/curing/server/main.go" ascii //weight: 1
        $x_1_6 = "/syscall/io_uring_register.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

