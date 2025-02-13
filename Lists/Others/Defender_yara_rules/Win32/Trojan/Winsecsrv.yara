rule Trojan_Win32_Winsecsrv_A_2147730376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winsecsrv.A!bit"
        threat_id = "2147730376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsecsrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rps.butldsk.com" wide //weight: 3
        $x_2_2 = {00 26 53 54 50 26 30 30 30 2e 30 30 30 26 32 2e 30 2e 30 2e 30 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 74 79 70 65 3d 67 65 74 2e 69 6e 73 74 2e 64 72 76 69 6e 66 6f 26 64 61 74 61 3d}  //weight: 2, accuracy: High
        $x_1_4 = "\\virtualbox" wide //weight: 1
        $x_1_5 = "\"IsInVMware\":" wide //weight: 1
        $x_1_6 = {00 49 6e 73 74 4d 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Winsecsrv_B_2147730377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Winsecsrv.B!bit"
        threat_id = "2147730377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsecsrv"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "29FHkehLFIHkdow(93p[lKFHOesrlwehjr23" ascii //weight: 1
        $x_1_2 = {00 61 64 69 6e 73 74 2e 64 6c 6c 00 64 6c 6c 5f 69 6e 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

