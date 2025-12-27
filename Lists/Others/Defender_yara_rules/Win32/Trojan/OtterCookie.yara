rule Trojan_Win32_OtterCookie_MA_2147956157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OtterCookie.MA!MTB"
        threat_id = "2147956157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OtterCookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "81"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "axios" wide //weight: 10
        $x_10_2 = "npm" wide //weight: 10
        $x_10_3 = "socket.io-client" wide //weight: 10
        $x_10_4 = "no-warnings" wide //weight: 10
        $x_10_5 = "makeLog" wide //weight: 10
        $x_10_6 = "clipboard" wide //weight: 10
        $x_10_7 = "wmic computersystem get model,manufacturer" wide //weight: 10
        $x_10_8 = "windowsHide: true" wide //weight: 10
        $x_1_9 = "vmware" wide //weight: 1
        $x_1_10 = "virtualbox" wide //weight: 1
        $x_1_11 = "qemu" wide //weight: 1
        $x_1_12 = "parallels" wide //weight: 1
        $x_1_13 = "hypervisor" wide //weight: 1
        $x_1_14 = "kvm" wide //weight: 1
        $x_1_15 = "xen" wide //weight: 1
        $x_1_16 = "bochs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

