rule Trojan_Win64_DriverLoader_RDA_2147849161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.RDA!MTB"
        threat_id = "2147849161"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 ee d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c6 2a c2 0f be c0 6b c8 37 40 02 ce 41 30 08 ff c6 4d 8d 40 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_ARA_2147892684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.ARA!MTB"
        threat_id = "2147892684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\MyWFHack\\CryKiller\\NEW BYPASS\\w1nner" ascii //weight: 2
        $x_2_2 = "limited\\x64\\Release\\w1nner.pdb" ascii //weight: 2
        $x_2_3 = "taskkill /f /im Battle.net.exe" ascii //weight: 2
        $x_2_4 = "taskkill /f /im ModernWarfare.exe" ascii //weight: 2
        $x_2_5 = "taskkill /f /im cod.exe" ascii //weight: 2
        $x_2_6 = "taskkill /f /im steam.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_DB_2147912746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.DB!MTB"
        threat_id = "2147912746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MyWFHack\\CryKiller\\NEW BYPASS\\w1nner" ascii //weight: 10
        $x_10_2 = "mw19 chair\\md ddls\\Black_Loader" ascii //weight: 10
        $x_10_3 = "mw19 srcs\\inj\\imgui inj\\plo1xmodz\\output\\mw19loader" ascii //weight: 10
        $x_10_4 = "SunsetInject\\x64\\Release\\SunsetInject" ascii //weight: 10
        $x_1_5 = "taskkill /f /im ModernWarfare.exe" ascii //weight: 1
        $x_1_6 = "taskkill /f /im cod.exe" ascii //weight: 1
        $x_1_7 = "taskkill /f /im steam.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DriverLoader_DA_2147913279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.DA!MTB"
        threat_id = "2147913279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 00 4e 00 4a 00 45 00 43 00 54 00 4f 00 52 00 [0-1] 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 70 00 64 00 62 00}  //weight: 10, accuracy: Low
        $x_10_2 = {49 4e 4a 45 43 54 4f 52 [0-1] 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_3 = "//mega.nz/file/" ascii //weight: 1
        $x_1_4 = "taskkill /FI \"IMAGENAME eq processhacker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DriverLoader_DC_2147913280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.DC!MTB"
        threat_id = "2147913280"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /FI \"IMAGENAME eq Taskmgr.exe" ascii //weight: 1
        $x_1_2 = "taskkill /FI \"IMAGENAME eq processhacker.exe" ascii //weight: 1
        $x_1_3 = "taskkill /FI \"IMAGENAME eq ida.exe" ascii //weight: 1
        $x_1_4 = "taskkill /FI \"IMAGENAME eq dnSpy.exe" ascii //weight: 1
        $x_1_5 = "taskkill /FI \"IMAGENAME eq KsDumper.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_RDB_2147919671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.RDB!MTB"
        threat_id = "2147919671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "you must disable vulnerable driver list to use kdmapper with intel driver" ascii //weight: 2
        $x_2_2 = "Your vulnerable driver list is enabled and have blocked the driver loading" ascii //weight: 2
        $x_1_3 = "Probably some anticheat or antivirus running blocking the load of vulnerable driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_ADRL_2147924394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.ADRL!MTB"
        threat_id = "2147924394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 57 c0 48 89 6c 24 30 48 03 fb c7 44 24 28 30 00 00 00 41 b9 30 00 00 00 48 89 6c 24 48 ba 48 20 00 80 48 89 6c 24 58 f3 0f 7f 44 24 64 48 8d 04 3e 89 6c 24 74 48 89 44 24 50 48 8d 44 24 48 48 89 44 24 20 c7 44 24 60}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_GNQ_2147933869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.GNQ!MTB"
        threat_id = "2147933869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 dd 03 44 ?? ?? 08 dd 03 44 38 ?? 18 dd 03 44 68 ?? d0 dd 03 44 50 ?? c0 dd ?? 44 c0 45 ?? ?? 52 6c 8d a3}  //weight: 10, accuracy: Low
        $x_10_2 = {43 31 3f 6c 2b a2 ?? ?? ?? ?? 52 0b eb d3 2f 86 f6 dc 6c 5c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_DriverLoader_SAO_2147934648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.SAO!MTB"
        threat_id = "2147934648"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /im WmiPrvSE* /f /t" ascii //weight: 2
        $x_2_2 = "protected by diwness protection" ascii //weight: 2
        $x_2_3 = "RaidPort" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DriverLoader_NR_2147945553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DriverLoader.NR!MTB"
        threat_id = "2147945553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DriverLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 54 24 10 88 4c 24 08 48 83 ec ?? 0f b6 05 5d b0 06 00 85 c0 74 0d}  //weight: 2, accuracy: Low
        $x_1_2 = "MyWFHack\\CryKiller\\NEW BYPASS\\w1nner" ascii //weight: 1
        $x_1_3 = "limited\\x64\\Release\\w1nner.pdb" ascii //weight: 1
        $x_1_4 = "hide" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

