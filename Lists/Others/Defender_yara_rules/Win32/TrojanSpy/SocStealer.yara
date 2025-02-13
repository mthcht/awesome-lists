rule TrojanSpy_Win32_SocStealer_B_2147728019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SocStealer.B!bit"
        threat_id = "2147728019"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SocStealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InstallSvc" ascii //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 2e 00 64 00 6c 00 6c 00 2d 00 62 00 69 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-32] 2f 00 58 00 36 00 34 00 2e 00 62 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 2e 00 64 00 6c 00 6c 00 2d 00 62 00 69 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-32] 2f 00 58 00 38 00 36 00 2e 00 62 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 2e 00 64 00 6c 00 6c 00 2d 00 62 00 69 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-32] 2f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 62 00 69 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_SocStealer_C_2147731538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SocStealer.C"
        threat_id = "2147731538"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SocStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\{6D187CC8-35BD-47F6-8760-D406AA1927B1}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_SocStealer_C_2147731538_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SocStealer.C"
        threat_id = "2147731538"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SocStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\{6D187CC8-35BD-47F6-8760-D406AA1927B1}" wide //weight: 1
        $x_1_2 = "InstallSvc" ascii //weight: 1
        $x_1_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 30 30 30 30 30 30 2d 30 30 30 30 30 30 2d 30 30 30 30 30 30 2d 30 30 30 30 30 30 2d 30 30 30 30 30 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_SocStealer_D_2147744053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SocStealer.D!ibt"
        threat_id = "2147744053"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SocStealer"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "business_id" ascii //weight: 1
        $x_1_2 = "credit_cards" ascii //weight: 1
        $x_1_3 = "FriendCount" ascii //weight: 1
        $x_1_4 = "https://www.facebook.com/" ascii //weight: 1
        $x_1_5 = "<script>bigPipe.beforePageletArrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

