rule Trojan_Win32_MshtaUrsnif_B_2147756288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MshtaUrsnif.B"
        threat_id = "2147756288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaUrsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "about:<hta:application><script>resizeTo(1,1);eval(new ActiveXObject('WScript.Shell').RegRead" wide //weight: 10
        $x_10_2 = {61 00 62 00 6f 00 75 00 74 00 3a 00 3c 00 68 00 74 00 61 00 3a 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 3e 00 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 6d 00 6f 00 76 00 65 00 54 00 6f 00 28 00 2d 00 [0-10] 29 00 3b 00 72 00 65 00 73 00 69 00 7a 00 65 00 54 00 6f 00 28 00 31 00 2c 00 31 00 29 00 3b 00 65 00 76 00 61 00 6c 00 28 00 6e 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 27 00 29 00 2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00}  //weight: 10, accuracy: Low
        $x_10_3 = "mshta.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MshtaUrsnif_C_2147756289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MshtaUrsnif.C"
        threat_id = "2147756289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaUrsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "new ActiveXObject" wide //weight: 100
        $x_100_2 = ".RegRead" wide //weight: 100
        $x_100_3 = {48 00 4b 00 43 00 55 00 [0-4] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 100, accuracy: Low
        $x_10_4 = "eval" wide //weight: 10
        $x_10_5 = "'e'+'val'" wide //weight: 10
        $x_10_6 = "'ev'+'al'" wide //weight: 10
        $x_10_7 = "'eva'+'l'" wide //weight: 10
        $x_10_8 = "'e'+'v'+'al'" wide //weight: 10
        $x_10_9 = "'e'+'va'+'l'" wide //weight: 10
        $x_10_10 = "'ev'+'a'+'l'" wide //weight: 10
        $x_10_11 = "'e'+'v'+'a'+'l'" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

