rule Trojan_Win32_CovertRAT_AMTB_2147962268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CovertRAT!AMTB"
        threat_id = "2147962268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CovertRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "__PERSIST__:__PERSIST_REMOVE____BEACON__:__DOWNLOAD__:__UPLOAD__|__HARVEST____ENCRYPT__:__DECRYPT__:__ELEVATE__" ascii //weight: 2
        $x_2_2 = {73 74 65 61 6c 65 72 2e 90 01 03 5f 5f 45 52 52 4f 52 5f 5f 3a 73 74 65 61 6c 65 72 2e 90 01 03 20 6e 6f 20 65 6e 63 6f 6e 74 72 61 64 6f 2e 20 45 6c 20 73 65 72 76 69 64 6f 72 20 64 65 62 65 20 73 75 62 69 72 6c 6f 20 70 72 69 6d 65 72 6f 2e}  //weight: 2, accuracy: High
        $x_2_3 = {72 61 6e 73 6f 6d 77 61 72 65 2e 90 01 03 5f 5f 45 52 52 4f 52 5f 5f 3a 72 61 6e 73 6f 6d 77 61 72 65 2e 90 01 03 20 6e 6f 20 65 6e 63 6f 6e 74 72 61 64 6f 2e 20 45 6c 20 73 65 72 76 69 64 6f 72 20 64 65 62 65 20 73 75 62 69 72 6c 6f 20 70 72 69 6d 65 72 6f 2e}  //weight: 2, accuracy: High
        $x_1_4 = "steal_credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

