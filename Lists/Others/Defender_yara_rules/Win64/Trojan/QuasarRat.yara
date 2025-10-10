rule Trojan_Win64_QuasarRat_NEAF_2147841430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRat.NEAF!MTB"
        threat_id = "2147841430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 18 4c 89 e9 48 89 fa 49 89 f0 e8 f3 88 00 00 30 18 48 89 ef eb d1}  //weight: 10, accuracy: High
        $x_5_2 = "github.com-1ecc6299db9ec823" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRat_NEAE_2147842135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRat.NEAE!MTB"
        threat_id = "2147842135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://spoofer.sytes.net/" ascii //weight: 5
        $x_2_2 = "Checking if user is admin..." ascii //weight: 2
        $x_2_3 = "start C:\\Windows\\System32\\IME" ascii //weight: 2
        $x_2_4 = "Starting spoofer..." ascii //weight: 2
        $x_2_5 = "Registry entries were spoofed." ascii //weight: 2
        $x_2_6 = "Removed any trace files found." ascii //weight: 2
        $x_2_7 = "ConsoleApplication.pdb" ascii //weight: 2
        $x_1_8 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_9 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_10 = "DisableBehaviorMonitoring" ascii //weight: 1
        $x_1_11 = "DisableScanOnRealtimeEnable" ascii //weight: 1
        $x_1_12 = "DisableOnAccessProtection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_QuasarRat_QL_2147954751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QuasarRat.QL!MTB"
        threat_id = "2147954751"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4c 24 40 48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 44 24 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

