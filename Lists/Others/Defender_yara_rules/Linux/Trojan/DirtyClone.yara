rule Trojan_Linux_DirtyClone_DA_2147972498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DirtyClone.DA!MTB"
        threat_id = "2147972498"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DirtyClone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] su entry overwritten; exec'ing su -> interactive root shell" ascii //weight: 1
        $x_1_2 = "[-] no setuid-root su found" ascii //weight: 1
        $x_1_3 = "[-] could not locate su entry point" ascii //weight: 1
        $x_1_4 = "[-] run me as an unprivileged user, not root" ascii //weight: 1
        $x_1_5 = "[-] --ubuntu: no usable aa-exec profile (trinity" ascii //weight: 1
        $x_1_6 = "execve su" ascii //weight: 1
        $x_1_7 = "open su" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

