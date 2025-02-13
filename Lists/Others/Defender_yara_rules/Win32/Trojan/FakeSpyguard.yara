rule Trojan_Win32_FakeSpyguard_132927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e 00 00 53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 6a 65 63 74 31 2e 64 6c 6c 00 53 65 74 48 6f 6f 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeSpyguard_132927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "*|domain|*" ascii //weight: 2
        $x_1_2 = "http://%domain%/content.php?se_id=%d&q=%s&page=%s&ua=%s&al=%s&aff_id=%s&sub_id=%s" ascii //weight: 1
        $x_1_3 = "http://%domain%/config.php" ascii //weight: 1
        $x_1_4 = "http://%domain%/update.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SPGuardMtx" ascii //weight: 1
        $x_1_2 = "http://gosgd.com" ascii //weight: 1
        $x_1_3 = "http://gosgd2.com" ascii //weight: 1
        $x_1_4 = "Spyware Guard 2008" ascii //weight: 1
        $x_1_5 = "Windows Security Center" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_7 = "\\Application Data\\Microsoft\\Protect\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_FakeSpyguard_132927_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/buy.html?track_id=" ascii //weight: 1
        $x_1_2 = "/key/?key=%s&email=%s" ascii //weight: 1
        $x_1_3 = {61 72 65 70 6f 72 74 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "TfmWarning3Attack" ascii //weight: 1
        $x_1_5 = "Agobot via WebDAV exploit" ascii //weight: 1
        $x_1_6 = "Do you want activate the antivirus software?" ascii //weight: 1
        $x_2_7 = {4c 6f 77 00 ff ff ff ff 04 00 00 00 48 69 67 68 00 00 00 00 ff ff ff ff 08 00 00 00 43 72 69 74 69 63 61 6c}  //weight: 2, accuracy: High
        $x_2_8 = "/activate/?key=%s&email=%s&track_id=%d&time=%s" ascii //weight: 2
        $x_2_9 = "/update/?action=get_base&base=1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 72 61 63 6b 5f 69 64 3d 25 64 00}  //weight: 2, accuracy: High
        $x_1_2 = {73 76 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 54 45 4d 4f 4e 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 70 79 77 61 72 65 20 47 75 61 72 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Application Data\\Microsoft\\Protect\\" ascii //weight: 3
        $x_1_2 = "shlconf.dat" ascii //weight: 1
        $x_1_3 = "rmlist.dat" ascii //weight: 1
        $x_1_4 = "Security32_win" ascii //weight: 1
        $x_1_5 = "rtime.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SC32X_Mutex" ascii //weight: 3
        $x_1_2 = "gosg2008.com" ascii //weight: 1
        $x_1_3 = "Windows Security Center reports that 'Spyware Guard" ascii //weight: 1
        $x_1_4 = "CoolTrayIcon1BalloonHintClick" ascii //weight: 1
        $x_1_5 = "/?track_id=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 53 65 63 75 72 69 74 79 5f 78 38 36 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 70 79 77 61 72 65 67 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_4 = {6a ff 68 01 00 1f 00 e8 ?? ?? ?? ?? 85 c0 75 ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 85 c0 77 ?? 6a 00}  //weight: 3, accuracy: Low
        $x_3_5 = {68 dc 05 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 6a 00 68 03 04 00 00 50 e8 ?? ?? ?? ?? eb}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 4d 69 63 72 6f 73 6f 66 74 20 (41|50) 44 61 74 61 5c}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6d 61 72 74 20 50 72 6f 74 65 63 74 6f 72 00}  //weight: 2, accuracy: High
        $x_2_3 = {50 65 72 73 6f 6e 61 6c 20 50 72 6f 74 65 63 74 6f 72 00}  //weight: 2, accuracy: High
        $x_1_4 = "Downloader.MDW\\Trojan" ascii //weight: 1
        $x_1_5 = "Virtumonde\\Trojan" ascii //weight: 1
        $x_1_6 = "Rebooter.J\\Trojan" ascii //weight: 1
        $x_1_7 = {53 69 73 74 65 6d 4b 65 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Security32_win" ascii //weight: 1
        $x_1_2 = "/?track_id=%d" ascii //weight: 1
        $x_1_3 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 72 65 70 6f 72 74 73 20 74 68 61 74 20 [0-32] 20 69 73 20 69 6e 61 63 74 69 76 65 2e}  //weight: 1, accuracy: Low
        $x_1_4 = "SC32X_Mutex" ascii //weight: 1
        $x_1_5 = "Note: Windows has detected an unregistered version of '" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_FakeSpyguard_132927_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/setup.php?track_id=%d" ascii //weight: 2
        $x_1_2 = "/?track_id=%d" ascii //weight: 1
        $x_1_3 = {73 76 63 68 6f 73 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 76 63 68 6f 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\Application Data\\Microsoft\\" ascii //weight: 1
        $x_1_6 = "\\Microsoft Private Data\\Microsoft\\" ascii //weight: 1
        $x_1_7 = {5c 4d 69 63 72 6f 73 6f 66 74 20 (41|50) 44 61 74 61 5c}  //weight: 1, accuracy: Low
        $x_1_8 = "Downloader.MDW\\Trojan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeSpyguard_132927_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeSpyguard"
        threat_id = "132927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpyguard"
        severity = "34"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Error 404 Not Found." ascii //weight: 1
        $x_1_2 = "Fatal error!" ascii //weight: 1
        $x_1_3 = "/setup.php?" ascii //weight: 1
        $x_1_4 = "/install/?" ascii //weight: 1
        $x_1_5 = "track_id=%d" ascii //weight: 1
        $x_1_6 = {43 54 45 4d 4f 4e 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_7 = "SOFTWARE\\Spyware Guard" ascii //weight: 1
        $x_1_8 = "This will install the trial version of Spyware Guard 20" ascii //weight: 1
        $x_1_9 = {53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 [0-2] 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

