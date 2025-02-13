rule Ransom_Win32_BabukLocker_MK_2147772002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukLocker.MK!MTB"
        threat_id = "2147772002"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "BABUK LOCKER" ascii //weight: 1
        $x_1_3 = "Your computers and servers are encrypted" ascii //weight: 1
        $x_1_4 = "!!! DANGER !!!" ascii //weight: 1
        $x_1_5 = "How To Restore Your Files.txt" ascii //weight: 1
        $x_1_6 = "ecdh_pub_k.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BabukLocker_MK_2147772002_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukLocker.MK!MTB"
        threat_id = "2147772002"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "47"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 10
        $x_5_2 = "ransomware" ascii //weight: 5
        $x_10_3 = "Your computers and servers are encrypted" ascii //weight: 10
        $x_10_4 = "nobody will pay us" ascii //weight: 10
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 61 00 62 00 75 00 6b 00 [0-16] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 62 61 62 75 6b [0-16] 2e 6f 6e 69 6f 6e 2f 6c 6f 67 69 6e 2e 70 68 70 3f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_7 = ".babyk" ascii //weight: 1
        $x_10_8 = "How To Restore Your Files.txt" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

