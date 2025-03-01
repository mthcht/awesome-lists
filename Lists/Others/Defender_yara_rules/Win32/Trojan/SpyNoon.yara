rule Trojan_Win32_SpyNoon_RT_2147779978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RT!MTB"
        threat_id = "2147779978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Isdjek.dll" ascii //weight: 1
        $x_1_2 = "ShellExecuteExA" ascii //weight: 1
        $x_1_3 = "ImageList_Destroy" ascii //weight: 1
        $x_1_4 = "Gxkeoxkzs" ascii //weight: 1
        $x_1_5 = "loadperf.dll" ascii //weight: 1
        $x_1_6 = "Project51.dll" ascii //weight: 1
        $x_1_7 = "SysListView32" ascii //weight: 1
        $x_1_8 = "\\something.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RR_2147782805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RR!MTB"
        threat_id = "2147782805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\proofing\\confound" ascii //weight: 1
        $x_1_2 = "fuoapcywhdth" ascii //weight: 1
        $x_1_3 = "zjqengvgsg" ascii //weight: 1
        $x_1_4 = "oyhkogssxdjwj" ascii //weight: 1
        $x_1_5 = "ptqvycvctgze" ascii //weight: 1
        $x_1_6 = "27059" ascii //weight: 1
        $x_1_7 = "snniubfsil" ascii //weight: 1
        $x_1_8 = "zhqtavogrwq" ascii //weight: 1
        $x_1_9 = "sqognkkgslx" ascii //weight: 1
        $x_1_10 = "gxcyimuwhjok" ascii //weight: 1
        $x_1_11 = "ewnblzkqmkvi" ascii //weight: 1
        $x_1_12 = "\\cloak\\confound.ra" ascii //weight: 1
        $x_1_13 = "oxqlxfzzek" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\hemlock\\fiesta" ascii //weight: 1
        $x_1_15 = "\\refuses\\enslaved.html" ascii //weight: 1
        $x_1_16 = "C:\\TEMP\\whludbgv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RRH_2147782912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RRH!MTB"
        threat_id = "2147782912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aiieqiayfdfl" wide //weight: 1
        $x_1_2 = "\\awfully\\friendships" wide //weight: 1
        $x_1_3 = "owugxjyiuyp" wide //weight: 1
        $x_1_4 = "zybecuqpopu" wide //weight: 1
        $x_1_5 = "ryvluztowybdu" wide //weight: 1
        $x_1_6 = "pbnfzfrkwusdv" wide //weight: 1
        $x_1_7 = "zddqhuwktbfm" wide //weight: 1
        $x_1_8 = "qcxlblxkau" wide //weight: 1
        $x_1_9 = "\\hemlock\\fundamentally\\opera.mdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_AA_2147795454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.AA!MTB"
        threat_id = "2147795454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 88 4d ff 0f b6 45 ff 05 9e 00 00 00 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff c1 fa 06 0f b6 45 ff c1 e0 02 0b d0 88 55 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_QEJ_2147797677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.QEJ!MTB"
        threat_id = "2147797677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "a -r -hp[PASSWORD] -v[SIZE] \"[OUT_PAT]\\[FILENAME]_[TIME]\" \"[IN_PATH]" wide //weight: 1
        $x_1_2 = {f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 88 84 0d f0 fb ff ff 8d 46 ff 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 88 84 0d f1 fb ff ff 8b c6 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 83 c6 04 88 84 3d ef fb ff ff 8b c7 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 87 ?? ?? ?? ?? 83 c7 04 88 84 0d f3 fb ff ff 83 c1 04 81 fe 02 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_SSM_2147807991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.SSM!MTB"
        threat_id = "2147807991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lmolkivjwcvmyqcpihhi" ascii //weight: 1
        $x_1_2 = "fxhn.dll" ascii //weight: 1
        $x_1_3 = "fttdjixnmho" ascii //weight: 1
        $x_1_4 = "nbkmmpmqoxc" ascii //weight: 1
        $x_1_5 = "bjokkjoeth" ascii //weight: 1
        $x_1_6 = "urhmxbamendvn" ascii //weight: 1
        $x_1_7 = "%APPDATA%" ascii //weight: 1
        $x_1_8 = "majidlecyr" ascii //weight: 1
        $x_1_9 = "mkqqnzkglpeilf" ascii //weight: 1
        $x_1_10 = "%TEMP%" ascii //weight: 1
        $x_1_11 = "eldjnylbwcsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPV_2147812917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPV!MTB"
        threat_id = "2147812917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 c4 00 00 00 8b 4d f8 03 4d fc 88 01 e9 be fe ff ff 8b 45 f8 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPW_2147812918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPW!MTB"
        threat_id = "2147812918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c1 ed 00 00 00 8b 55 f8 03 55 fc 88 0a e9 54 fe ff ff 8b 45 f8 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPX_2147812999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPX!MTB"
        threat_id = "2147812999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c3 82 18 00 00 81 c1 ee 8c 00 00 81 ea ed 1c 01 00 2d 03 51 01 00 ba 7b 4f 01 00 81 e3 85 69 01 00 4a c2 3f e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPY_2147813000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPY!MTB"
        threat_id = "2147813000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 03 55 fc 88 0a e9 ?? ?? ff ff 8b 45 f8 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPS_2147815533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPS!MTB"
        threat_id = "2147815533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f8 03 55 fc 88 0a 8b 45 f8 03 45 fc 8a 08 80 e9 01 8b 55 f8 03 55 fc 88 0a e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RPO_2147818712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RPO!MTB"
        threat_id = "2147818712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 80 34 01 ?? 8b 4d f0 80 04 01 ?? 8b 4d f0 80 04 01 ?? 8b 4d f0 80 04 01 ?? 8b 4d f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RF_2147840926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RF!MTB"
        threat_id = "2147840926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Importedx765ant Fileedx765s/Proedx765file" wide //weight: 1
        $x_1_2 = "Walledx765ets/Binanedx765ce" wide //weight: 1
        $x_1_3 = "Walledx765ets/Ethedx765ereum" wide //weight: 1
        $x_1_4 = "Guarda" wide //weight: 1
        $x_1_5 = "%localappdata%\\Chroedx765mium\\Useedx765r Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyNoon_RK_2147843088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyNoon.RK!MTB"
        threat_id = "2147843088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 08 85 c0 74 1a 83 c0 fe 85 c0 7c 10 8a 54 08 01 32 14 08 80 f2 78 88 14 08 48 79 f0 80 31 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

