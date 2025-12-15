rule Trojan_Win32_OffLoader_RPY_2147846047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RPY!MTB"
        threat_id = "2147846047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\server\\share" wide //weight: 1
        $x_1_2 = {65 00 73 00 73 00 2e 00 66 00 6f 00 6f 00 64 00 63 00 72 00 69 00 62 00 2e 00 73 00 69 00 74 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {77 00 77 00 2e 00 70 00 68 00 70}  //weight: 1, accuracy: High
        $x_1_4 = "TUNINSTALLPROGRESSFORM" ascii //weight: 1
        $x_1_5 = "TDOWNLOADWIZARDPAGE" ascii //weight: 1
        $x_1_6 = "DOWNLOADTEMPORARYFILE" ascii //weight: 1
        $x_1_7 = "TONDOWNLOADPROGRESS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EM_2147848213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EM!MTB"
        threat_id = "2147848213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 61 00 6d 00 6d 00 65 00 72 00 63 00 61 00 6b 00 65 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 69 00 6c 00 6c 00 2e 00 70 00 68 00 70}  //weight: 1, accuracy: High
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EM_2147848213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EM!MTB"
        threat_id = "2147848213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {61 00 61 00 2e 00 6c 00 6f 00 63 00 6b 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 37}  //weight: 9, accuracy: High
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EM_2147848213_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EM!MTB"
        threat_id = "2147848213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 72 00 75 00 69 00 74 00 62 00 75 00 6c 00 62 00 2e 00 78 00 79 00 7a 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70}  //weight: 10, accuracy: High
        $x_1_2 = "\\\\server\\share" wide //weight: 1
        $x_1_3 = "restart the computer now" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EM_2147848213_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EM!MTB"
        threat_id = "2147848213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 61 00 2e 00 6c 00 6f 00 63 00 6b 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 32 00 32 00 36 00 38 00 26 00 74 00 3d 00 34 00 36 00 31 00 35 00 34 00 33 00 33 00 34 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 51 00 57 00 4e 00 30 00 61 00 58 00 5a 00 68 00 64 00 47 00 39 00 79 00 49 00 43 00 73 00 67 00 51 00 33 00 4a 00 68 00 59 00 32 00 73 00 67 00 4b 00 79 00 42 00 54 00 5a 00 58 00 4a 00 70 00 59 00 57 00 77 00 67 00 4b 00 79 00 42 00 4c 00 5a 00 58 00 6b 00 3d}  //weight: 9, accuracy: High
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EM_2147848213_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EM!MTB"
        threat_id = "2147848213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 72 00 69 00 63 00 65 00 6d 00 61 00 72 00 6b 00 65 00 74 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 72 00 65 00 71 00 2e 00 70 00 68 00 70}  //weight: 10, accuracy: High
        $x_10_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 72 00 75 00 69 00 74 00 62 00 75 00 6c 00 62 00 2e 00 78 00 79 00 7a 00 2f 00 72 00 65 00 71 00 73 00 2e 00 70 00 68 00 70}  //weight: 10, accuracy: High
        $x_10_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 31 00 32 00 2e 00 32 00 35 00 33 00 2e 00 37 00 34 00 2f 00 70 00 69 00 6e 00 65 00 61 00 70 00 70 00 6c 00 65 00 2e 00 70 00 68 00 70}  //weight: 10, accuracy: High
        $x_1_4 = "sysuserinfoname" wide //weight: 1
        $x_1_5 = "sysuserinfoorg" wide //weight: 1
        $x_1_6 = "*.exe,*.dll,*.chm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_EN_2147850145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EN!MTB"
        threat_id = "2147850145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "teethbubble.icu/ido.php" wide //weight: 1
        $x_1_2 = "ido.exe" wide //weight: 1
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EN_2147850145_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EN!MTB"
        threat_id = "2147850145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 68 00 6f 00 73 00 74 00 77 00 61 00 78 00 2e 00 78 00 79 00 7a 00 2f 00 72 00 69 00 74 00 2e 00 70 00 68 00 70}  //weight: 10, accuracy: High
        $x_1_2 = "\\\\server\\share" wide //weight: 1
        $x_1_3 = "restart the computer now" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EN_2147850145_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EN!MTB"
        threat_id = "2147850145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pointdinosaurs.xyz/ido.php" wide //weight: 1
        $x_1_2 = "streetpage.icu/idos.php" wide //weight: 1
        $x_1_3 = "ido.exe" wide //weight: 1
        $x_1_4 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EN_2147850145_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EN!MTB"
        threat_id = "2147850145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {67 00 68 00 6f 00 73 00 74 00 77 00 61 00 78 00 2e 00 78 00 79 00 7a 00 2f 00 72 00 69 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 34 00 39 00 26 00 74 00 3d 00 34 00 36 00 33 00 36 00 39 00 39 00 39 00 35 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 52 00 6d 00 6c 00 32 00 5a 00 55 00 30 00 67 00 49 00 45 00 64 00 55 00 51 00 53 00 42 00 57 00 49 00 43 00 42 00 56 00 62 00 48 00 52 00 79 00 59 00 53 00 42 00 4d 00 62 00 33 00 63 00 67 00 52 00 57 00 35 00 6b 00 49 00 46 00 42 00 44 00 49 00 45 00 5a 00 51 00 55 00 79 00 42 00 43 00 54 00 30 00 39 00 54 00 56 00 43 00 42 00 51 00 59 00 57 00 4e 00 72 00 49 00 45 00 5a 00 76 00 63 00 69 00 41 00 30 00 52 00 30 00 49 00 67 00 4c 00 6d 00 56 00 34 00 5a 00 51 00 3d 00 3d}  //weight: 9, accuracy: High
        $x_9_2 = {67 00 68 00 6f 00 73 00 74 00 77 00 61 00 78 00 2e 00 78 00 79 00 7a 00 2f 00 72 00 69 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33}  //weight: 9, accuracy: High
        $x_1_3 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            ((2 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_EN_2147850145_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EN!MTB"
        threat_id = "2147850145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 72 00 6f 00 77 00 61 00 64 00 76 00 65 00 72 00 74 00 69 00 73 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 72 00 61 00 74 00 2e 00 70 00 68 00 70}  //weight: 9, accuracy: High
        $x_9_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 68 00 6f 00 73 00 74 00 77 00 61 00 78 00 2e 00 78 00 79 00 7a 00 2f 00 72 00 69 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 37 00 39 00 32 00 26 00 74 00 3d 00 34 00 36 00 34 00 37 00 37 00 37 00 36 00 33 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 52 00 47 00 39 00 33 00 62 00 6d 00 78 00 76 00 59 00 57 00 51 00 67 00 51 00 6d 00 78 00 68 00 63 00 33 00 52 00 33 00 59 00 58 00 5a 00 6c 00 52 00 6c 00 67 00 67 00 51 00 6d 00 6c 00 79 00 5a 00 48 00 4d 00 67 00 51 00 6d 00 6c 00 69 00 62 00 47 00 55 00 67 00 65 00 6d 00 6c 00 77 00 4c 00 6d 00 56 00 34 00 5a 00 51 00 3d 00 3d 00 26 00 73 00 75 00 62 00 3d}  //weight: 9, accuracy: High
        $x_1_3 = "server\\share" ascii //weight: 1
        $x_1_4 = "install [name] on your computer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EK_2147851026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EK!MTB"
        threat_id = "2147851026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {77 00 61 00 73 00 68 00 64 00 69 00 6e 00 6e 00 65 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 67 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 9, accuracy: High
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EH_2147851159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EH!MTB"
        threat_id = "2147851159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = {66 00 6c 00 6f 00 63 00 6b 00 73 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 73 00 69 00 74 00 65 00 2f 00 65 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 34 00 38 00 26 00 74 00 3d 00 34 00 36 00 33 00 37 00 33 00 30 00 33 00 31 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 51 00 58 00 52 00 6f 00 5a}  //weight: 9, accuracy: High
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_DAT_2147851226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.DAT!MTB"
        threat_id = "2147851226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 65 00 62 00 63 00 6f 00 6d 00 70 00 61 00 6e 00 69 00 6f 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 6e 00 61 00 6e 00 6f 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 3d 00 49 00 54 00 32 00 31 00 30 00 38 00 30 00 31}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASA_2147852850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASA!MTB"
        threat_id = "2147852850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 67 00 71 00 75 00 61 00 72 00 74 00 65 00 72 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 31 00 31 00 26 00 74 00 3d 00 34 00 36 00 36 00 32 00 33 00 31 00 38 00 37 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 63 00 47 00 68 00 77 00 49 00 48 00 52 00 6f 00 5a 00 58 00 52 00 70 00 64 00 47 00 78 00 6c 00 49 00 43 00 35 00 6c 00 65 00 47 00 55}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASB_2147887398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASB!MTB"
        threat_id = "2147887398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 62 00 74 00 2e 00 70 00 6f 00 73 00 69 00 74 00 69 00 6f 00 6e 00 62 00 65 00 64 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 3d 00 69 00 6e 00 6e 00 6f 00 26 00 72 00 3d 00 6f 00 66 00 66 00 65 00 72 00 5f 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 26 00 72 00 6b 00 3d 00 79 00 65 00 73 00 26 00 6f 00 3d 00 31 00 36 00 35 00 30 00 26 00 61}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASC_2147888300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASC!MTB"
        threat_id = "2147888300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 67 00 71 00 75 00 61 00 72 00 74 00 65 00 72 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 31 00 31 00 26 00 74 00 3d 00 34 00 36 00 37 00 32 00 39 00 35 00 34 00 39 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 63 00 47 00 68 00 77 00 49 00 48 00 52 00 6f 00 5a 00 58 00 52 00 70 00 64 00 47 00 78 00 6c 00 49 00 43 00 35 00 6c 00 65 00 47 00 55 00 3d 00 26 00 73 00 75 00 62}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EB_2147888903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EB!MTB"
        threat_id = "2147888903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 67 00 71 00 75 00 61 00 72 00 74 00 65 00 72 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 31 00 31 00 26 00 74 00 3d 00 34 00 36 00 36 00 38 00 39 00 30 00 38 00 32 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 63 00 47 00 68 00 77 00 49 00 48 00 52 00 6f 00 5a 00 58 00 52 00 70 00 64 00 47 00 78 00 6c 00 49 00 43 00 35 00 6c 00 65 00 47 00 55 00 3d 00 26 00 73 00 75 00 62 00 3d 00 32 00 34 00 37 00 37 00 0b 21}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 69 00 7a 00 65 00 73 00 68 00 6f 00 63 00 6b 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 31 00 31 00 26 00 74 00 3d 00 34 00 36 00 36 00 38 00 39 00 30 00 38 00 32 00 26 00 74 00 69 00 74 00 6c 00 65 00 3d 00 63 00 47 00 68 00 77 00 49 00 48 00 52 00 6f 00 5a 00 58 00 52 00 70 00 64 00 47 00 78 00 6c 00 49 00 43 00 35 00 6c 00 65 00 47 00 55 00 3d 00 26 00 73 00 75 00 62 00 3d 00 32 00 34 00 37 00 37 00 0b 21}  //weight: 1, accuracy: High
        $x_1_3 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASD_2147889046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASD!MTB"
        threat_id = "2147889046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://angerdistribution.site/gampa.php?p=38" wide //weight: 1
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASE_2147889299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASE!MTB"
        threat_id = "2147889299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 64 00 64 00 2e 00 63 00 6f 00 6d 00 70 00 61 00 72 00 69 00 73 00 6f 00 6e 00 73 00 6f 00 6e 00 67 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d 00 33}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASF_2147889300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASF!MTB"
        threat_id = "2147889300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 6e 00 67 00 65 00 72 00 64 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6f 00 6e 00 2e 00 73 00 69 00 74 00 65 00 2f 00 67 00 61 00 6d 00 70 00 61 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASG_2147889407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASG!MTB"
        threat_id = "2147889407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 64 00 64 00 2e 00 63 00 6f 00 6d 00 70 00 61 00 72 00 69 00 73 00 6f 00 6e 00 73 00 6f 00 6e 00 67 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASH_2147889481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASH!MTB"
        threat_id = "2147889481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 67 00 71 00 75 00 61 00 72 00 74 00 65 00 72 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 67 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 64 00 64 00 2e 00 63 00 6f 00 6d 00 70 00 61 00 72 00 69 00 73 00 6f 00 6e 00 73 00 6f 00 6e 00 67 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00 3f 00 63 00 63 00 3d}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_OffLoader_ASI_2147890044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASI!MTB"
        threat_id = "2147890044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 6c 00 61 00 6e 00 65 00 73 00 76 00 61 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 72 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 61 00 76 00 65 00 2e 00 65 00 61 00 72 00 74 00 68 00 71 00 75 00 61 00 6b 00 65 00 73 00 68 00 61 00 70 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_OffLoader_ASJ_2147890493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASJ!MTB"
        threat_id = "2147890493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 61 00 2e 00 6c 00 6f 00 63 00 6b 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 32 00 32 00 36 00 38 00 26 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6f 00 6f 00 6c 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 78 00 31 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 35 00 35 00 38 00 26 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6f 00 6f 00 6c 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 78 00 31 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 32 00 30 00 26 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6f 00 6f 00 6c 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 78 00 31 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 38 00 39 00 31 00 26 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_5 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_6 = "restart the computer now" wide //weight: 1
        $x_1_7 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_OffLoader_ASK_2147890499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASK!MTB"
        threat_id = "2147890499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 69 00 65 00 70 00 75 00 6d 00 70 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 75 00 6d 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASL_2147891174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASL!MTB"
        threat_id = "2147891174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6f 00 6f 00 6c 00 63 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 78 00 31 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 ?? 00 ?? 00 ?? 00 26 00 74 00 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_EC_2147891514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.EC!MTB"
        threat_id = "2147891514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 00 6f 00 6e 00 3d 00 33 00 38 00 36 00 26 00 73 00 70 00 6f 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {67 00 61 00 6d 00 65 00 2e 00 65 00 67 00 67 00 73 00 6c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 64 00 3d 00 69 00 6e 00 6e 00 6f 00 26 00 72 00 3d 00 6f 00 66 00 66 00 65 00 72 00 5f 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 26 00 72 00 6b}  //weight: 1, accuracy: High
        $x_1_3 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_OffLoader_ASM_2147893003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASM!MTB"
        threat_id = "2147893003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6d 00 6f 00 69 00 73 00 74 00 2e 00 73 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASN_2147893100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASN!MTB"
        threat_id = "2147893100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://e.spadesheep.xyz/x.php?p=3492&t=" wide //weight: 1
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASO_2147895629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASO!MTB"
        threat_id = "2147895629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://cookchildren.online/ki.php?p=" wide //weight: 1
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASP_2147895856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASP!MTB"
        threat_id = "2147895856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 78 00 2e 00 70 00 72 00 6f 00 73 00 65 00 66 00 72 00 69 00 65 00 6e 00 64 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASQ_2147896262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASQ!MTB"
        threat_id = "2147896262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 76 00 69 00 65 00 77 00 77 00 65 00 69 00 67 00 68 00 74 00 2e 00 78 00 79 00 7a 00 2f 00 74 00 72 00 79 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASQ_2147896262_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASQ!MTB"
        threat_id = "2147896262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 72 00 6f 00 75 00 70 00 63 00 6f 00 62 00 77 00 65 00 62 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 65 00 6c 00 64 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 39 00 33 00 34 00 26 00 74 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_RDA_2147897275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RDA!MTB"
        threat_id = "2147897275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//groupcobweb.online/eld.php?" wide //weight: 2
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_RDB_2147897284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RDB!MTB"
        threat_id = "2147897284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//guideslave.online/he.php?" wide //weight: 2
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASR_2147897432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASR!MTB"
        threat_id = "2147897432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 6f 00 6f 00 64 00 2e 00 63 00 65 00 6c 00 6c 00 61 00 72 00 73 00 6d 00 61 00 73 00 68 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6f 00 75 00 2e 00 64 00 69 00 6d 00 65 00 66 00 6c 00 6f 00 77 00 65 00 72 00 73 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_AST_2147897825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AST!MTB"
        threat_id = "2147897825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 73 00 74 00 66 00 6f 00 72 00 6b 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 77 00 69 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_RDC_2147897833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RDC!MTB"
        threat_id = "2147897833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//restfork.website/win.php" wide //weight: 2
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_RDD_2147898334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RDD!MTB"
        threat_id = "2147898334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//celerypie.online/asts.php" wide //weight: 2
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASU_2147898607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASU!MTB"
        threat_id = "2147898607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 61 00 67 00 70 00 6c 00 61 00 79 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 62 00 61 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 69 00 72 00 65 00 62 00 69 00 72 00 74 00 68 00 64 00 61 00 79 00 2e 00 73 00 69 00 74 00 65 00 2f 00 62 00 61 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 65 00 66 00 72 00 69 00 65 00 6e 00 64 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 6f 00 63 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6f 00 6f 00 6b 00 73 00 61 00 6d 00 75 00 73 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6f 00 63 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_5 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_6 = "restart the computer now" wide //weight: 1
        $x_1_7 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_OffLoader_RDE_2147898785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.RDE!MTB"
        threat_id = "2147898785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//d.minutepin.website/x.php?" wide //weight: 2
        $x_1_2 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASW_2147898815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASW!MTB"
        threat_id = "2147898815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 65 00 73 00 74 00 66 00 6f 00 72 00 6b 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 62 00 6f 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASX_2147899270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASX!MTB"
        threat_id = "2147899270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 61 00 6c 00 73 00 65 00 2e 00 61 00 70 00 70 00 61 00 72 00 65 00 6c 00 73 00 69 00 6c 00 76 00 65 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6a 00 75 00 6d 00 70 00 77 00 65 00 69 00 67 00 68 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ASY_2147899834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASY!MTB"
        threat_id = "2147899834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://birthdayrhythm.online/ra.php?pe=n&p" wide //weight: 2
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AAAT_2147899898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AAAT!MTB"
        threat_id = "2147899898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6b 00 6e 00 6f 00 74 00 74 00 68 00 72 00 69 00 6c 00 6c 00 2e 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AAAW_2147900019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AAAW!MTB"
        threat_id = "2147900019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 6f 00 66 00 61 00 69 00 63 00 69 00 63 00 6c 00 65 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 6c 00 69 00 6d 00 2e 00 70 00 68 00 70}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASZ_2147900499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASZ!MTB"
        threat_id = "2147900499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 69 00 72 00 74 00 68 00 64 00 61 00 79 00 72 00 68 00 79 00 74 00 68 00 6d 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 72 00 61 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 6c 00 62 00 6f 00 77 00 73 00 74 00 72 00 75 00 63 00 74 00 75 00 72 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 70 00 69 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 3d}  //weight: 2, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ASAA_2147900649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAA!MTB"
        threat_id = "2147900649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6d 00 69 00 63 00 65 00 74 00 72 00 61 00 69 00 6e 00 73 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAB_2147901289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAB!MTB"
        threat_id = "2147901289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 75 00 6c 00 62 00 6e 00 75 00 74 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAC_2147901371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAC!MTB"
        threat_id = "2147901371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 61 00 69 00 6c 00 74 00 68 00 72 00 69 00 6c 00 6c 00 2e 00 78 00 79 00 7a 00 2f 00 66 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 3d 00 6e 00 26 00 70 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAD_2147902010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAD!MTB"
        threat_id = "2147902010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "brassforce.site/ploss.php?a=" ascii //weight: 2
        $x_2_2 = "sto.farmscene.website/track" ascii //weight: 2
        $x_2_3 = {76 63 72 65 64 69 73 74 5f 78 36 34 2e 65 78 65 [0-16] 5c 69 6e 65 74 63 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_4 = "weaksecurity" ascii //weight: 2
        $x_1_5 = "VERYSILENT /PASSWORD=NtIRVUpMK9ZD30Nf98220" ascii //weight: 1
        $x_1_6 = "VERYSILENT /SUPPRESSMSGBOXES" ascii //weight: 1
        $x_1_7 = "only/ppba" ascii //weight: 1
        $x_1_8 = "qn CAMPAIGN=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ASAE_2147902481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAE!MTB"
        threat_id = "2147902481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 6b 00 79 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f 00 61 00 3d}  //weight: 2, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPA_2147902788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPA!MTB"
        threat_id = "2147902788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vestmountain.site/bli.php" ascii //weight: 5
        $x_2_2 = "woodlevel.site/tracker/thank_you.php" ascii //weight: 2
        $x_5_3 = "seedagreement.site/asiko.php" ascii //weight: 5
        $x_2_4 = "sto.farmscene.website" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ASAF_2147902897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAF!MTB"
        threat_id = "2147902897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 72 00 6f 00 75 00 70 00 77 00 69 00 6e 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 62 00 6f 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 3d}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 69 00 6e 00 65 00 67 00 75 00 69 00 74 00 61 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 62 00 6f 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 3d 00 31 00 26 00 70 00 3d}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPC_2147903252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPC!MTB"
        threat_id = "2147903252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "wastetop.website/run.php" ascii //weight: 5
        $x_2_2 = "thoughtmeal.site/tracker/thank_you" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAG_2147903865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAG!MTB"
        threat_id = "2147903865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "drinkbattle.xyz/asiko.php?" wide //weight: 2
        $x_2_2 = "shipstream.xyz/asiko.php?" wide //weight: 2
        $x_2_3 = "Are you sure that you want to stop download?" wide //weight: 2
        $x_2_4 = {73 00 65 00 74 00 5f 00 ?? 00 2e 00 65 00 78 00 65 00 22 00 20 00 2f 00 71 00 6e 00 20 00 43 00 41 00 4d 00 50 00 41 00 49 00 47 00 4e 00 3d}  //weight: 2, accuracy: Low
        $x_2_5 = {73 00 65 00 74 00 5f 00 30 00 2e 00 65 00 78 00 65 00 22 00 20 00 2d 00 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 20 00 2d 00 2d 00 61 00 6c 00 6c 00 75 00 73 00 65 00 72 00 73 00 3d 00 30}  //weight: 2, accuracy: High
        $x_1_6 = "only/ppba" wide //weight: 1
        $x_1_7 = "Software\\sdfwsdfs6df" wide //weight: 1
        $x_1_8 = "Software\\AmbaSoftGmbH" wide //weight: 1
        $x_1_9 = "VERYSILENT /PASSWORD=NtIRVUpMK9ZD30Nf98220  -token mtn1co3fo4gs5vwq -subid" wide //weight: 1
        $x_1_10 = "SP- /VERYSILENT /SUPPRESSMSGBOXES /INSTALLERSHOWNELSEWHERE /sid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_GPD_2147903882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPD!MTB"
        threat_id = "2147903882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "chessfang.online/pp.php?pe" ascii //weight: 5
        $x_2_2 = "educationcoach.site" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GDAA_2147903894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GDAA!MTB"
        threat_id = "2147903894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://towndust.website/af.php?" wide //weight: 2
        $x_2_2 = "://educationcoach.site/aft.php?" wide //weight: 2
        $x_2_3 = "://voyageblood.online/glam.php?" wide //weight: 2
        $x_2_4 = "://servantzephyr.online/tracker/thank_you.php?" wide //weight: 2
        $x_1_5 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_GPE_2147904281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPE!MTB"
        threat_id = "2147904281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ducksstop.site/glam.php?pe" ascii //weight: 5
        $x_2_2 = "jellyfishtrees.site/tracker/thank_you.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GE_2147904428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GE!MTB"
        threat_id = "2147904428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\YCL" ascii //weight: 1
        $x_1_2 = "glovefire.site/dub.php?fz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAH_2147904474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAH!MTB"
        threat_id = "2147904474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pleasurefly.online/tracker/thank_you.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
        $x_1_3 = "I want to manually reboot later" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_HNS_2147904570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.HNS!MTB"
        threat_id = "2147904570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InnoDownloadPlugin/1.5" ascii //weight: 1
        $x_1_2 = ".php?spot=1&a=" ascii //weight: 1
        $x_1_3 = "--silent --allusers=0" ascii //weight: 1
        $x_5_4 = ".php?fz=&d=nsis&msg=&r=offer_execution&rk=yes&o=" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_HNS_2147904570_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.HNS!MTB"
        threat_id = "2147904570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "--silent --allusers=0" ascii //weight: 1
        $x_1_2 = ".php?fz=" ascii //weight: 1
        $x_1_3 = ".php?spot=" ascii //weight: 1
        $x_10_4 = {64 00 3d 00 69 00 6e 00 6e 00 6f 00 26 00 72 00 3d 00 6f 00 66 00 66 00 65 00 72 00 5f 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 26 00 ?? ?? ?? ?? 3d 00 79 00 65 00 73 00 26 00 6f 00 3d 00}  //weight: 10, accuracy: Low
        $x_10_5 = {64 3d 69 6e 6e 6f 26 72 3d 6f 66 66 65 72 5f 65 78 65 63 75 74 69 6f 6e 26 ?? ?? ?? ?? 3d 79 65 73 26 6f 3d}  //weight: 10, accuracy: Low
        $x_2_6 = {2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 5f 00 [0-16] 2e 00 70 00 68 00 70 00 3f 00 74 00 69 00 6d 00 3d 00}  //weight: 2, accuracy: Low
        $x_2_7 = {2e 6f 6e 6c 69 6e 65 2f 74 72 61 63 6b 5f [0-16] 2e 70 68 70 3f 74 69 6d 3d}  //weight: 2, accuracy: Low
        $x_2_8 = {73 00 74 00 61 00 74 00 65 00 73 00 2e 00 6c 00 6f 00 67 00 0b 12 00 00 00 00 00 15 00 00 60 01 14 00 00 00 66 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_GF_2147904579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GF!MTB"
        threat_id = "2147904579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\sdfwsdfs6df" ascii //weight: 1
        $x_1_2 = "Software\\SPoloCleaner" ascii //weight: 1
        $x_1_3 = "peacesleep.site/dub.php?fz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPFL_2147904609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPFL!MTB"
        threat_id = "2147904609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "laughyard.site/blip.php" wide //weight: 2
        $x_2_2 = "committeecircle.website/tracker/thank_you.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPGA_2147904664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPGA!MTB"
        threat_id = "2147904664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "veilorange.website/blip.php" wide //weight: 3
        $x_2_2 = "additionwriting.site/tracker/thank_you.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPDI_2147904780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPDI!MTB"
        threat_id = "2147904780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "detailquicksand.website/reap.php" wide //weight: 2
        $x_2_2 = "planegrain.website/tracker/thank_you.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPLL_2147904781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPLL!MTB"
        threat_id = "2147904781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "numberquince.xyz/li.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPLL_2147904781_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPLL!MTB"
        threat_id = "2147904781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/magiclunch.icu/trr.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GK_2147904920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GK!MTB"
        threat_id = "2147904920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\AmbaSoftGmbH" ascii //weight: 1
        $x_1_2 = "Software\\SPoloCleaner" ascii //weight: 1
        $x_1_3 = "Software\\sdfwsdfs6df" ascii //weight: 1
        $x_1_4 = "d=nsis&msg=&r=offer_execution&rk=no" ascii //weight: 1
        $x_1_5 = "set_0.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPJL_2147904927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPJL!MTB"
        threat_id = "2147904927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "save.windowstone.website/track_polosEU.php" ascii //weight: 4
        $x_2_2 = "jewelbasketball.xyz/lica.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPF_2147905042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPF!MTB"
        threat_id = "2147905042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "throatbalance.xyz/reap.php?pe" ascii //weight: 5
        $x_2_2 = "skirtrose.site/tracker/thank_you.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAI_2147905152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAI!MTB"
        threat_id = "2147905152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "save.windowstone.website/track_" wide //weight: 2
        $x_1_2 = "restart the computer now" wide //weight: 1
        $x_1_3 = "Yes, I would like to view the README file" wide //weight: 1
        $x_1_4 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPAK_2147905551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPAK!MTB"
        threat_id = "2147905551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "gold-proxy.net/licensing-agreement.php" ascii //weight: 4
        $x_2_2 = "restart the computer now" wide //weight: 2
        $x_1_3 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAJ_2147905583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAJ!MTB"
        threat_id = "2147905583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pp.toothbrushindustry.online/track_" wide //weight: 2
        $x_2_2 = "oceanriddle.website/pre2.php" wide //weight: 2
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
        $x_1_5 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPUP_2147905975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPUP!MTB"
        threat_id = "2147905975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "blowrain.website/njg.php" wide //weight: 2
        $x_2_2 = "enginewine.xyz/njk.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASAK_2147906196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASAK!MTB"
        threat_id = "2147906196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "joinfront.xyz/pos.php?" wide //weight: 2
        $x_2_2 = "cabledust.website/pos.php?" wide //weight: 2
        $x_1_3 = "goal.harborhorse.online/track_" wide //weight: 1
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
        $x_1_6 = "server\\share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_JMAA_2147906380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.JMAA!MTB"
        threat_id = "2147906380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 b2 9b fa ff 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52}  //weight: 2, accuracy: High
        $x_2_2 = {e8 cf 74 fa ff 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 34 89 34 89 34 89 34 89 34 89 34}  //weight: 2, accuracy: High
        $x_1_3 = "/silent" wide //weight: 1
        $x_1_4 = "/weaksecurity" wide //weight: 1
        $x_1_5 = "/nocookies" wide //weight: 1
        $x_1_6 = "/popup" wide //weight: 1
        $x_1_7 = "/resume" wide //weight: 1
        $x_1_8 = "/useragent" wide //weight: 1
        $x_1_9 = "/connecttimeout" wide //weight: 1
        $x_1_10 = "/tostackconv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_GPG_2147907487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPG!MTB"
        threat_id = "2147907487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "galandskiyher5.com/privacy" ascii //weight: 5
        $x_2_2 = "digitalpulsedata.com/tos" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADJ_2147911511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADJ!MTB"
        threat_id = "2147911511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://farmfang.fun/rlo.php?" wide //weight: 1
        $x_1_2 = "https://farmfang.fun/tracker/thank_you.php?" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPOD_2147911718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPOD!MTB"
        threat_id = "2147911718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sideair.hair/tracker/thank_you.php" wide //weight: 1
        $x_1_2 = "sideair.hair/rlo.php" wide //weight: 1
        $x_1_3 = "restart the computer now" wide //weight: 1
        $x_1_4 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPMC_2147911876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPMC!MTB"
        threat_id = "2147911876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dollshands.icu/arpk.php" wide //weight: 2
        $x_2_2 = "shakesleep.bond/arpt.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPH_2147912074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPH!MTB"
        threat_id = "2147912074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "forkcast.website/art.php?pid" ascii //weight: 5
        $x_2_2 = "forkcast.website/rlo.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADI_2147912161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADI!MTB"
        threat_id = "2147912161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 61 00 76 00 65 00 2e 00 70 00 6c 00 61 00 63 00 65 00 67 00 6f 00 6c 00 64 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 5f 00 70 00 72 00 6f 00 78 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 74 00 61 00 74 00 65 00 73 00 2e 00 6c 00 6f 00 67}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADK_2147912451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADK!MTB"
        threat_id = "2147912451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://laughvein.hair/rlo.php?" wide //weight: 1
        $x_1_2 = "https://laughvein.hair/tracker/thank_you.php?" wide //weight: 1
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
        $x_1_6 = "states.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPI_2147912719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPI!MTB"
        threat_id = "2147912719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nightauthority.xyz/rlo.php?d" ascii //weight: 5
        $x_2_2 = "nightauthority.xyz/tracker/thank_you.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_PEAA_2147912751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.PEAA!MTB"
        threat_id = "2147912751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://cattlebusiness.icu/rlo.php" wide //weight: 2
        $x_2_2 = "https://cattlebusiness.icu/art.php" wide //weight: 2
        $x_2_3 = "http://cattlebusiness.icu/coo.php" wide //weight: 2
        $x_1_4 = "https://cattlebusiness.icu/tracker/thank_you.php" wide //weight: 1
        $x_1_5 = "\\\\server\\share" wide //weight: 1
        $x_1_6 = "restart the computer now" ascii //weight: 1
        $x_1_7 = "Yes, I would like to view the README file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ADL_2147912813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADL!MTB"
        threat_id = "2147912813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://brotherpopcorn.website/tracker/thank_you.php?" wide //weight: 2
        $x_2_2 = "https://oceanriddle.website/tracker/thank_you.php?" wide //weight: 2
        $x_2_3 = "https://monkeyagreement.fun/tracker/thank_you.php?" wide //weight: 2
        $x_1_4 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_5 = "restart the computer now" wide //weight: 1
        $x_1_6 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_SPBC_2147912881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPBC!MTB"
        threat_id = "2147912881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/chintray.website/outo.php" wide //weight: 5
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPJ_2147912978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPJ!MTB"
        threat_id = "2147912978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "advancedmanager.io/eula" ascii //weight: 5
        $x_2_2 = "digitalpulsedata.com/tos" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADM_2147913074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADM!MTB"
        threat_id = "2147913074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://valuescent.website/coo.php?" wide //weight: 2
        $x_2_2 = "http://save.placegold.website/track_inl2.php?" wide //weight: 2
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADN_2147913211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADN!MTB"
        threat_id = "2147913211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://whipunit.hair/tracker/thank_you.php?" wide //weight: 2
        $x_2_2 = "http://whipunit.hair/coo.php?" wide //weight: 2
        $x_2_3 = "http://caretouch.hair/rlo.php?" wide //weight: 2
        $x_2_4 = "https://caretouch.hair/tracker/thank_you.php?trk" wide //weight: 2
        $x_1_5 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_6 = "restart the computer now" wide //weight: 1
        $x_1_7 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_SPPC_2147914041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPPC!MTB"
        threat_id = "2147914041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/hornquiver.icu/kond.php" wide //weight: 3
        $x_3_2 = "/pizzasreason.icu/kund.php" wide //weight: 3
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SDRL_2147915674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SDRL!MTB"
        threat_id = "2147915674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/cherryforce.xyz/gota.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SDJL_2147915832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SDJL!MTB"
        threat_id = "2147915832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/zooschool.website/pe/start/index.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPWQ_2147915935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPWQ!MTB"
        threat_id = "2147915935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/crownsmoke.xyz/but.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPWQ_2147915935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPWQ!MTB"
        threat_id = "2147915935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "boxgrandfather.info/poli.php" ascii //weight: 4
        $x_4_2 = "chickenslevel.xyz/polis.php" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPKM_2147916324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPKM!MTB"
        threat_id = "2147916324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/thrillsand.icu/alo.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SCBC_2147917129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SCBC!MTB"
        threat_id = "2147917129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/sheetcopper.xyz/hc.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADO_2147918023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADO!MTB"
        threat_id = "2147918023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "amountnorth.icu/abb.php?" wide //weight: 3
        $x_1_2 = "/nocookies" wide //weight: 1
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SSBC_2147918988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SSBC!MTB"
        threat_id = "2147918988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/coughexistence.icu/sch.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SDWQ_2147920085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SDWQ!MTB"
        threat_id = "2147920085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/expertdirection.icu/sip.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADP_2147920914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADP!MTB"
        threat_id = "2147920914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "motionspace.space/klo.php?" wide //weight: 3
        $x_1_2 = "/nocookies" wide //weight: 1
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADP_2147920914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADP!MTB"
        threat_id = "2147920914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "berryfog.xyz/doi.php?pe=" wide //weight: 3
        $x_3_2 = "rainroad.icu/dio.php?pe" wide //weight: 3
        $x_1_3 = "/nocookies" wide //weight: 1
        $x_1_4 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SHLQ_2147921747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SHLQ!MTB"
        threat_id = "2147921747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/thoughtwren.website/one.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SDQB_2147921751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SDQB!MTB"
        threat_id = "2147921751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/connect.vasebox.art/pe/start/index.php" ascii //weight: 2
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPHP_2147921753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPHP!MTB"
        threat_id = "2147921753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/buttoncamera.sbs/ark.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SDDP_2147921754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SDDP!MTB"
        threat_id = "2147921754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/personteam.cfd/mik.php?" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SHSP_2147922125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SHSP!MTB"
        threat_id = "2147922125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/shapework.cfd/srp.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SSSD_2147922745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SSSD!MTB"
        threat_id = "2147922745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/souprabbits.xyz/nao.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADQ_2147923277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADQ!MTB"
        threat_id = "2147923277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "chancethroat.icu/ajt.php?pe" wide //weight: 3
        $x_3_2 = "coalcrime.icu/ait.php?pe" wide //weight: 3
        $x_1_3 = "/nocookies" wide //weight: 1
        $x_1_4 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPSJ_2147923470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPSJ!MTB"
        threat_id = "2147923470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/quartersystem.xyz/dro.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPZJ_2147924048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPZJ!MTB"
        threat_id = "2147924048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/crimeauthority.cfd/tiu.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPM_2147924201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPM!MTB"
        threat_id = "2147924201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vaseliquid.xyz/pe/build.php?pe=" ascii //weight: 5
        $x_5_2 = "sisterobservation.icu/mou.php?pe=" ascii //weight: 5
        $x_2_3 = "Internet Explorer\\Quick Launch" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_SPTJ_2147924624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPTJ!MTB"
        threat_id = "2147924624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/fairiespet.icu/fro.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SXTJ_2147924853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SXTJ!MTB"
        threat_id = "2147924853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/treeskittens.cfd/arn.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADR_2147925676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADR!MTB"
        threat_id = "2147925676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "increasegrandmother.xyz/tru.php?pe" wide //weight: 3
        $x_3_2 = "grapecub.sbs/trm.php?pe" wide //weight: 3
        $x_1_3 = "/nocookies" wide //weight: 1
        $x_1_4 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPVJ_2147926175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPVJ!MTB"
        threat_id = "2147926175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/developmentmask.cfd/nod.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SVVJ_2147926297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SVVJ!MTB"
        threat_id = "2147926297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/ironwealth.sbs/lic.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SCVC_2147926676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SCVC!MTB"
        threat_id = "2147926676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/attractionknowledge.sbs/sny.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SCZC_2147926799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SCZC!MTB"
        threat_id = "2147926799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/creatorbedroom.cfd/winn.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPOC_2147927238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPOC!MTB"
        threat_id = "2147927238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/requestants.sbs/dec.php" wide //weight: 3
        $x_2_2 = "/silent" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SGLP_2147927403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SGLP!MTB"
        threat_id = "2147927403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/lockplay.sbs/glad.php" wide //weight: 2
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPYE_2147927682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPYE!MTB"
        threat_id = "2147927682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/middlesilk.cfd/wel.php" wide //weight: 3
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPP_2147929203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPP!MTB"
        threat_id = "2147929203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 26 2b 8f 31 3a 46 0e 00 00 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPPA_2147929275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPPA!MTB"
        threat_id = "2147929275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 19 c5 9b f4 3a 46 0e 00 00 e8 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AYHA_2147929710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AYHA!MTB"
        threat_id = "2147929710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://grandfatherproduce.sbs/riku.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPPB_2147929908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPPB!MTB"
        threat_id = "2147929908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 ef b2 ae 79}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AEIA_2147929928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AEIA!MTB"
        threat_id = "2147929928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://tinfuel.sbs/yie.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AKIA_2147930102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AKIA!MTB"
        threat_id = "2147930102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://creatorfold.icu/pon.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_APIA_2147930698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.APIA!MTB"
        threat_id = "2147930698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://toothdigestion.xyz/emi.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPIA_2147930970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPIA!MTB"
        threat_id = "2147930970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "/curvetrail.xyz/nue.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANJA_2147931538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANJA!MTB"
        threat_id = "2147931538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://linenwomen.icu/ero.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AGJA_2147931896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AGJA!MTB"
        threat_id = "2147931896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://tablepancake.icu/doo.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPVA_2147932703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPVA!MTB"
        threat_id = "2147932703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//hotfriction.xyz/lkoo.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AVKA_2147932945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AVKA!MTB"
        threat_id = "2147932945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://thrillghost.xyz/biz.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AILA_2147933498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AILA!MTB"
        threat_id = "2147933498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://stomachcoil.xyz/wol.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANLA_2147933647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANLA!MTB"
        threat_id = "2147933647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://hairteeth.icu/ryt.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPAC_2147934969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPAC!MTB"
        threat_id = "2147934969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//zipperwork.icu/rid.php" wide //weight: 4
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ADNA_2147935296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ADNA!MTB"
        threat_id = "2147935296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://massminister.icu/she.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPLS_2147935355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPLS!MTB"
        threat_id = "2147935355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//poisonhorn.xyz/ryto.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AKNA_2147935399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AKNA!MTB"
        threat_id = "2147935399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://weathereffect.xyz/noo.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AMNA_2147935548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AMNA!MTB"
        threat_id = "2147935548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://planewool.icu/unk.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SBLS_2147935934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SBLS!MTB"
        threat_id = "2147935934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//grainink.website/hio.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AEOA_2147936191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AEOA!MTB"
        threat_id = "2147936191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://suitpicture.xyz/ers.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SAA_2147936287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SAA!MTB"
        threat_id = "2147936287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//frontthroat.xyz/jeto.php" ascii //weight: 2
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AMMA_2147936390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AMMA!MTB"
        threat_id = "2147936390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://zipperwork.icu/rid.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANOA_2147936451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANOA!MTB"
        threat_id = "2147936451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://hotsecretary.icu/mon.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AVOA_2147936787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AVOA!MTB"
        threat_id = "2147936787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://apparelafternoon.icu/rout.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AEPA_2147937016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AEPA!MTB"
        threat_id = "2147937016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://bloodcrown.xyz/limp.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AVJA_2147937050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AVJA!MTB"
        threat_id = "2147937050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://shameservant.icu/lko.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANO_2147937059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANO!MTB"
        threat_id = "2147937059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "aa.lockstart.host/st.php" wide //weight: 3
        $x_1_2 = "restart the computer now" wide //weight: 1
        $x_1_3 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AMPA_2147937255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AMPA!MTB"
        threat_id = "2147937255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://yarnwool.xyz/grun.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_APPA_2147937366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.APPA!MTB"
        threat_id = "2147937366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://hourdigestion.icu/rums.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AVPA_2147937711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AVPA!MTB"
        threat_id = "2147937711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://quillexperience.icu/jump.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SELS_2147938051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SELS!MTB"
        threat_id = "2147938051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//wishson.icu/ido.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AIQA_2147938256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AIQA!MTB"
        threat_id = "2147938256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://pointdinosaurs.xyz/ido.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPPC_2147938486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPPC!MTB"
        threat_id = "2147938486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 33 a5 c9 0f 3a 46 0e}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANP_2147938909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANP!MTB"
        threat_id = "2147938909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "teethbubble.icu/ido.php" wide //weight: 3
        $x_3_2 = "picklebat.xyz/idos.php" wide //weight: 3
        $x_1_3 = "nocookies" wide //weight: 1
        $x_1_4 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SKIA_2147939136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SKIA!MTB"
        threat_id = "2147939136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://veinfear.cfd/caro.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANQ_2147939239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANQ!MTB"
        threat_id = "2147939239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "pancakebag.xyz/bik.php" wide //weight: 3
        $x_3_2 = "plotcake.icu/biks.php" wide //weight: 3
        $x_1_3 = "nocookies" wide //weight: 1
        $x_1_4 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANS_2147939414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANS!MTB"
        threat_id = "2147939414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rabbitsweek.icu/bik.php?" wide //weight: 3
        $x_3_2 = "factlow.xyz/biks.php?" wide //weight: 3
        $x_1_3 = "nocookies" wide //weight: 1
        $x_1_4 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANU_2147939534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANU!MTB"
        threat_id = "2147939534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "birthteeth.xyz/oil.php?" wide //weight: 3
        $x_3_2 = "vasebird.xyz/oils.php?" wide //weight: 3
        $x_1_3 = "nocookies" wide //weight: 1
        $x_1_4 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASRA_2147939723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASRA!MTB"
        threat_id = "2147939723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://carriageletter.icu/oil.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANA_2147939889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANA!MTB"
        threat_id = "2147939889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "seeddevelopment.icu/lov.php?" wide //weight: 3
        $x_3_2 = "threadbranch.xyz/lovs.php?" wide //weight: 3
        $x_1_3 = "nocookies" wide //weight: 1
        $x_1_4 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPPD_2147940234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPPD!MTB"
        threat_id = "2147940234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "auntberry.xyz/pe/start/index.php" ascii //weight: 5
        $x_2_2 = "/VERYSILENT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ATSA_2147940629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ATSA!MTB"
        threat_id = "2147940629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://ricebreath.icu/tri.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AXSA_2147940762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AXSA!MTB"
        threat_id = "2147940762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://crowsalt.icu/tri.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AGTA_2147941046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AGTA!MTB"
        threat_id = "2147941046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://boneyarn.xyz/lui.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ALTA_2147941134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ALTA!MTB"
        threat_id = "2147941134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://crackarithmetic.icu/glo.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANTA_2147941146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANTA!MTB"
        threat_id = "2147941146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://carriageletter.icu/oil.php?" ascii //weight: 3
        $x_3_2 = "://troublesisters.xyz/oils.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AQTA_2147941251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AQTA!MTB"
        threat_id = "2147941251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://yamhot.icu/ier.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AZTA_2147941476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AZTA!MTB"
        threat_id = "2147941476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "://truckobservation.icu/aar.php?" ascii //weight: 10
        $x_10_2 = "://mintborder.icu/bie.php?" ascii //weight: 10
        $x_10_3 = "://pointrespect.xyz/hrt.php?" ascii //weight: 10
        $x_10_4 = "://dogsjar.xyz/hit.php?" ascii //weight: 10
        $x_10_5 = "://skintemper.xyz/biu.php?" ascii //weight: 10
        $x_10_6 = "://governmentmoney.icu/glf.php?" ascii //weight: 10
        $x_10_7 = "://robinkiss.info/krr.php?" ascii //weight: 10
        $x_10_8 = "://eventauthority.info/kkk.php?" ascii //weight: 10
        $x_10_9 = "://yearducks.info/yyy.php?" ascii //weight: 10
        $x_10_10 = "://creampump.info/bno.php?" ascii //weight: 10
        $x_10_11 = "://nutkittens.info/kul.php?" ascii //weight: 10
        $x_10_12 = "://visitorboy.info/rtr.php?" ascii //weight: 10
        $x_10_13 = "://punishmentslave.info/tre.php?" ascii //weight: 10
        $x_10_14 = "://roofspade.info/fou.php?" ascii //weight: 10
        $x_1_15 = "/silent" ascii //weight: 1
        $x_1_16 = "/weaksecurity" ascii //weight: 1
        $x_1_17 = "/nocookies" ascii //weight: 1
        $x_1_18 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_AMUA_2147941782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AMUA!MTB"
        threat_id = "2147941782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://teethelbow.icu/tri.php?" ascii //weight: 4
        $x_4_2 = "://ministerkiss.xyz/tris.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZBT_2147942851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZBT!MTB"
        threat_id = "2147942851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://sparkdonkey.icu/nii.php?" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AH_2147945057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AH!MTB"
        threat_id = "2147945057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "seabusiness.xyz/fkis.php" wide //weight: 3
        $x_3_2 = "sonplane.info/fki.php?pe" wide //weight: 3
        $x_3_3 = "cakestoothbrush.icu/lui.php?pe" wide //weight: 3
        $x_3_4 = "sodabedroom.xyz/luis.php" wide //weight: 3
        $x_3_5 = "teethelbow.icu/tri.php?pe" wide //weight: 3
        $x_3_6 = "ministerkiss.xyz/tris.php?pe" wide //weight: 3
        $x_3_7 = "frogtruck.xyz/mee.php?" wide //weight: 3
        $x_3_8 = "quincestreet.icu/mees.php?" wide //weight: 3
        $x_3_9 = "creatoreggs.icu/oiu.php?" wide //weight: 3
        $x_3_10 = "buttonsize.xyz/oius.php?pe" wide //weight: 3
        $x_3_11 = "eventauthority.info/kkk.php?pe" wide //weight: 3
        $x_3_12 = "quincepart.icu/kkks.php?" wide //weight: 3
        $x_3_13 = "biketoes.xyz/slf.php?pe" wide //weight: 3
        $x_3_14 = "smellstamp.icu/slfs.php" wide //weight: 3
        $x_3_15 = "railwaytime.xyz/slfs.php" wide //weight: 3
        $x_3_16 = "laughincome.icu/slf.php?pe" wide //weight: 3
        $x_3_17 = "memoryneck.info/goo.php?pe" wide //weight: 3
        $x_3_18 = "volleyballsong.xyz/goos.php" wide //weight: 3
        $x_3_19 = "airplanemove.info/yut.php?pe" wide //weight: 3
        $x_3_20 = "producesound.xyz/yuts.php?" wide //weight: 3
        $x_3_21 = "stoveweather.info/too.php?pe" wide //weight: 3
        $x_3_22 = "yarncontool.icu/toos.php?" wide //weight: 3
        $x_3_23 = "daughtercemetery.xyz/par.php?pe" wide //weight: 3
        $x_3_24 = "committeedinner.icu/pars.php?pe" wide //weight: 3
        $x_1_25 = "nocookies" wide //weight: 1
        $x_1_26 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_SPV_2147945075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPV!MTB"
        threat_id = "2147945075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sonplane.info/fki.php?pe" wide //weight: 3
        $x_3_2 = "seabusiness.xyz/fkis.php" wide //weight: 3
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AHYA_2147945298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AHYA!MTB"
        threat_id = "2147945298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://memoryneck.info/goo.php?" ascii //weight: 4
        $x_4_2 = "://volleyballsong.xyz/goos.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GPPK_2147946057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GPPK!MTB"
        threat_id = "2147946057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b2 35 00 80}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AVZA_2147946657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AVZA!MTB"
        threat_id = "2147946657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://visitorboy.info/rtr.php?" ascii //weight: 4
        $x_4_2 = "://hallchance.xyz/rtrs.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SKAP_2147946987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SKAP!MTB"
        threat_id = "2147946987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "airporticicle.info/xcx.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZHQ_2147947602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZHQ!MTB"
        threat_id = "2147947602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://tripshape.xyz/gons.php?" ascii //weight: 3
        $x_3_2 = "://thingspies.info/gon.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPAP_2147947861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPAP!MTB"
        threat_id = "2147947861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "spoonporter.xyz/kiys.php" wide //weight: 4
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPGP_2147948702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPGP!MTB"
        threat_id = "2147948702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "toothbrushdoctor.xyz/docs.php" wide //weight: 4
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AFCB_2147948946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AFCB!MTB"
        threat_id = "2147948946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://religionrose.info/mit.php?" ascii //weight: 4
        $x_4_2 = "://brakeslave.xyz/mits.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_APCB_2147949299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.APCB!MTB"
        threat_id = "2147949299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://hairlace.info/gnu.php?" ascii //weight: 4
        $x_4_2 = "://taxsmile.xyz/gnus.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ATCB_2147949414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ATCB!MTB"
        threat_id = "2147949414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://matchcabbage.info/lju.php?" ascii //weight: 4
        $x_4_2 = "://wirevegetable.info/ljus.php?" ascii //weight: 4
        $x_4_3 = "://roadtrousers.info/rnu.php?" ascii //weight: 4
        $x_4_4 = "://shirtapparatus.xyz/rnus.php?" ascii //weight: 4
        $x_4_5 = "://insurancemorning.info/bet.php?" ascii //weight: 4
        $x_4_6 = "://belieffield.info/bets.php?" ascii //weight: 4
        $x_4_7 = "://hourchess.info/plu.php?" ascii //weight: 4
        $x_4_8 = "://woolreward.xyz/plus.php?" ascii //weight: 4
        $x_1_9 = "/silent" ascii //weight: 1
        $x_1_10 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_SPEP_2147949492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPEP!MTB"
        threat_id = "2147949492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "mineicicle.info/hmo.php" wide //weight: 4
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SASP_2147949936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SASP!MTB"
        threat_id = "2147949936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "maidjellyfish.info/tru.php" ascii //weight: 4
        $x_4_2 = "thingsidea.info/trus.php" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ACEB_2147950984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ACEB!MTB"
        threat_id = "2147950984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://inkseed.info/naj.php?" ascii //weight: 4
        $x_4_2 = "://developmentgovernment.xyz/najs.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZVR_2147951060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZVR!MTB"
        threat_id = "2147951060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://birthdayreward.xyz/xcxs.php?pe=" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "/weaksecurity" ascii //weight: 1
        $x_1_4 = "/nocookies" ascii //weight: 1
        $x_1_5 = "/resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ANEB_2147951366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ANEB!MTB"
        threat_id = "2147951366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://screwengine.info/mir.php?" ascii //weight: 4
        $x_4_2 = "://increaserock.xyz/mirs.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPRP_2147951714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPRP!MTB"
        threat_id = "2147951714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "roadrecord.xyz/arus.php" wide //weight: 4
        $x_1_2 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ASEB_2147951974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ASEB!MTB"
        threat_id = "2147951974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://pailchange.info/okut.php?" ascii //weight: 4
        $x_4_2 = "://celeryact.xyz/okuts.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_MKV_2147952087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.MKV!MTB"
        threat_id = "2147952087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://beliefdirection.xyz/gimys.php?" ascii //weight: 4
        $x_4_2 = "://spadesense.info/gimy.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ACFB_2147952173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ACFB!MTB"
        threat_id = "2147952173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://industryfinger.info/arki.php?" ascii //weight: 4
        $x_4_2 = "://expertpowder.xyz/arkis.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_PGOF_2147952221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.PGOF!MTB"
        threat_id = "2147952221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "roofcakes.info/mark.php" ascii //weight: 2
        $x_2_2 = "vestsheet.xyz/marks.php" ascii //weight: 2
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_PGOF_2147952221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.PGOF!MTB"
        threat_id = "2147952221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://framestove.info/ajto.php?" ascii //weight: 2
        $x_2_2 = "http://joinfall.xyz/ajtos.php?" ascii //weight: 2
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_PGOF_2147952221_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.PGOF!MTB"
        threat_id = "2147952221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://armytreatment.info/ytri.php?" ascii //weight: 2
        $x_2_2 = "http://armroute.xyz/ytris.php?" ascii //weight: 2
        $x_1_3 = "Do you want to reboot now?" ascii //weight: 1
        $x_1_4 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_PGOF_2147952221_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.PGOF!MTB"
        threat_id = "2147952221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://exampleporter.info/niec.php?" ascii //weight: 2
        $x_2_2 = "http://honeyshirt.xyz/niecs.php?" ascii //weight: 2
        $x_1_3 = "Do you want to reboot now?" ascii //weight: 1
        $x_1_4 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_MKZ_2147952367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.MKZ!MTB"
        threat_id = "2147952367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://needporter.info/jimy.php?" ascii //weight: 4
        $x_4_2 = "://talktoe.xyz/jimys.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZEN_2147952447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZEN!MTB"
        threat_id = "2147952447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://unitmoon.xyz/golys.php?" ascii //weight: 4
        $x_4_2 = "://trainbear.info/goly.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZMN_2147952858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZMN!MTB"
        threat_id = "2147952858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://umbrellapower.info/bhuy.php?" ascii //weight: 4
        $x_4_2 = "://doordime.xyz/bhuys.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AWFB_2147953076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AWFB!MTB"
        threat_id = "2147953076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://spaderock.info/wdry.php?" ascii //weight: 4
        $x_4_2 = "://boxlevel.xyz/wdrys.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_GAQ_2147953144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.GAQ!MTB"
        threat_id = "2147953144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? 1d 00 ?? ?? 0e 00 00 64 36 00 ?? ?? ?? ?? be 9b 0e 00 00 3e 0d 00 ?? ?? ?? ?? 00 00 01 00 0d}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_KES_2147953391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.KES!MTB"
        threat_id = "2147953391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://suitmemory.info/qort.php?" ascii //weight: 4
        $x_4_2 = "://additionhydrant.xyz/qorts.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
        $x_1_5 = "Reboot now" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AEGB_2147953542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AEGB!MTB"
        threat_id = "2147953542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://routepickle.info/cort.php?" ascii //weight: 4
        $x_4_2 = "://hydrantice.xyz/corts.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZYN_2147953706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZYN!MTB"
        threat_id = "2147953706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://pipehair.info/myrt.php?" ascii //weight: 4
        $x_4_2 = "://respectrail.xyz/myrts.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAA_2147953848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAA!MTB"
        threat_id = "2147953848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://kettleghost.info/hirv.php?" ascii //weight: 4
        $x_4_2 = "://bloodcommittee.xyz/hirvs.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
        $x_1_5 = "Reboot now" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPEQ_2147954065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPEQ!MTB"
        threat_id = "2147954065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "reasoncoal.xyz/gywes.php" ascii //weight: 4
        $x_4_2 = "glassgovernment.info/gywe.php" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ABHB_2147954307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ABHB!MTB"
        threat_id = "2147954307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://traymitten.info/nulo.php?" ascii //weight: 4
        $x_4_2 = "://positionpail.xyz/nulos.php?" ascii //weight: 4
        $x_4_3 = "://wireswim.info/tuyo.php?" ascii //weight: 4
        $x_4_4 = "://plantswaves.xyz/tuyos.php?" ascii //weight: 4
        $x_1_5 = "/silent" ascii //weight: 1
        $x_1_6 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_POFF_2147954587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.POFF!MTB"
        threat_id = "2147954587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-42] 2e 00 69 00 6e 00 66 00 6f 00 2f 00 [0-15] 2e 00 70 00 68 00 70 00 3f 00 [0-4] 3d 00 6e 00 26 00 6b 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 74 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 [0-10] 3d 00 [0-255] 26 00 [0-10] 3d 00 00 00 2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 00 00 67 00 65 00 74 00 00 00 31 00 30 00 32 00 33 00 ?? ?? ?? ?? ?? ?? ?? ?? 35 00 30 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-42] 2e 00 78 00 79 00 7a 00 2f 00 [0-15] 2e 00 70 00 68 00 70 00 3f 00 [0-4] 3d 00 6e 00 26 00 6b 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 74 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 [0-10] 3d 00 [0-255] 26 00 [0-10] 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: Low
        $x_3_2 = {68 74 00 74 00 70 3a 2f 2f [0-42] 2e 69 6e 66 6f 2f [0-15] 2e 70 68 70 3f [0-4] 3d 6e 26 6b 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 74 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 [0-10] 3d [0-255] 26 [0-10] 3d 00 00 2f 73 69 6c 65 6e 74 00 00 67 65 74 00 00 31 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 00 74 00 70 3a 2f 2f [0-42] 2e 78 79 7a 2f [0-15] 2e 70 68 70 3f [0-4] 3d 6e 26 6b 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 74 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 [0-10] 3d [0-255] 26 [0-10] 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_2_3 = "Do you want to reboot now?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_POFF_2147954587_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.POFF!MTB"
        threat_id = "2147954587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-42] 2e 00 69 00 6e 00 66 00 6f 00 2f 00 [0-15] 2e 00 70 00 68 00 70 00 3f 00 [0-4] 3d 00 6e 00 26 00 6b 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 74 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 [0-10] 3d 00 [0-255] 26 00 73 00 75 00 62 00 3d 00 00 00 2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 00 00 67 00 65 00 74 00 00 00 31 00 30 00 32 00 33 00 ?? ?? ?? ?? ?? ?? ?? ?? 35 00 30 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-42] 2e 00 78 00 79 00 7a 00 2f 00 [0-15] 2e 00 70 00 68 00 70 00 3f 00 [0-4] 3d 00 6e 00 26 00 6b 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 74 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 00 [0-10] 3d 00 [0-255] 26 00 73 00 75 00 62 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: Low
        $x_3_2 = {68 74 00 74 00 70 3a 2f 2f [0-42] 2e 69 6e 66 6f 2f [0-15] 2e 70 68 70 3f [0-4] 3d 6e 26 6b 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 74 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 [0-10] 3d [0-255] 26 73 75 62 3d 00 00 2f 73 69 6c 65 6e 74 00 00 67 65 74 00 00 31 30 32 33 ?? ?? ?? ?? ?? ?? ?? ?? 35 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 74 00 74 00 70 3a 2f 2f [0-42] 2e 78 79 7a 2f [0-15] 2e 70 68 70 3f [0-4] 3d 6e 26 6b 3d ?? ?? ?? ?? ?? ?? ?? ?? 26 74 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 [0-10] 3d [0-255] 26 73 75 62 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_2_3 = "Do you want to reboot now?" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_AOHB_2147954778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AOHB!MTB"
        threat_id = "2147954778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://aftermathargument.info/brat.php?" ascii //weight: 4
        $x_4_2 = "://crowdcats.xyz/brats.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SMR_2147954896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SMR!MTB"
        threat_id = "2147954896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://bookgiants.info/grdi.php?" ascii //weight: 4
        $x_4_2 = "://unittoe.xyz/grdis.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SZR_2147955015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SZR!MTB"
        threat_id = "2147955015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://hammerocean.info/milu.php?" ascii //weight: 4
        $x_4_2 = "://underweargroup.xyz/milus.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAC_2147955275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAC!MTB"
        threat_id = "2147955275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://passengerweather.info/grxs.php?" ascii //weight: 4
        $x_4_2 = "://actioncloth.xyz/grxss.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAC_2147955275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAC!MTB"
        threat_id = "2147955275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://selectionscarecrow.info/awas.php?" ascii //weight: 4
        $x_4_2 = "://earthkittens.xyz/awass.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_NNM_2147955498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.NNM!MTB"
        threat_id = "2147955498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://fogants.info/ampi.php?" ascii //weight: 4
        $x_4_2 = "://behaviorplanes.xyz/ampis.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZFL_2147955915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZFL!MTB"
        threat_id = "2147955915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://tripbike.info/gryt.php?" ascii //weight: 3
        $x_3_2 = "://riddlecare.xyz/gryts.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_LDM_2147956058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.LDM!MTB"
        threat_id = "2147956058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://receiptclass.info/grym.php?" ascii //weight: 4
        $x_4_2 = "://borderexperience.xyz/gryms.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ACJB_2147956276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ACJB!MTB"
        threat_id = "2147956276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://bikeszinc.info/anjo.php?" ascii //weight: 4
        $x_4_2 = "://wealthdiscussion.xyz/anjos.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAB_2147956463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAB!MTB"
        threat_id = "2147956463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://dressthroat.info/bnjo.php?" ascii //weight: 4
        $x_4_2 = "://pleasurejelly.xyz/bnjos.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AWJB_2147956768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AWJB!MTB"
        threat_id = "2147956768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://partsmoke.info/hook.php?" ascii //weight: 4
        $x_4_2 = "://vesselcreator.xyz/hooks.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZZL_2147956917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZZL!MTB"
        threat_id = "2147956917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://picturesurprise.info/hiik.php?" ascii //weight: 3
        $x_3_2 = "://borderrabbits.xyz/hiiks.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_MOF_2147957134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.MOF!MTB"
        threat_id = "2147957134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://scenttrousers.info/ikut.php?" ascii //weight: 4
        $x_4_2 = "://kettlesnake.xyz/ikuts.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAD_2147957279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAD!MTB"
        threat_id = "2147957279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://cellardirection.info/goop.php" ascii //weight: 4
        $x_4_2 = "://jeansscience.xyz/goops.php" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_BAE_2147957480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.BAE!MTB"
        threat_id = "2147957480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://bulbneck.xyz/absas.php?" ascii //weight: 4
        $x_4_2 = "://skinbelieve.info/absa.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZUK_2147957743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZUK!MTB"
        threat_id = "2147957743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://bucketdegree.xyz/vetos.php?" ascii //weight: 3
        $x_3_2 = "://pushminister.info/veto.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZBJ_2147957955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZBJ!MTB"
        threat_id = "2147957955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://hallkiss.info/gree.php?" ascii //weight: 3
        $x_3_2 = "://pumptrains.xyz/grees.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZDJ_2147958039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZDJ!MTB"
        threat_id = "2147958039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://rangefowl.xyz/octos.php?" ascii //weight: 3
        $x_3_2 = "://impulseice.info/octo.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_POFA_2147958200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.POFA!MTB"
        threat_id = "2147958200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://questiontendency.xyz/allis.php?" ascii //weight: 4
        $x_4_2 = "http://tempercream.info/alli.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ZMJ_2147958413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZMJ!MTB"
        threat_id = "2147958413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://activitywound.xyz/genos.php?" ascii //weight: 3
        $x_3_2 = "://signchickens.info/geno.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZPJ_2147958533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZPJ!MTB"
        threat_id = "2147958533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://boardvolleyball.info/asst.php?" ascii //weight: 3
        $x_3_2 = "://brakeseed.xyz/assts.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZSJ_2147958615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZSJ!MTB"
        threat_id = "2147958615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://mountainbattle.info/anka.php?" ascii //weight: 3
        $x_3_2 = "://channelhealth.xyz/ankas.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_POFB_2147958781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.POFB!MTB"
        threat_id = "2147958781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://afterthoughtliquid.info/kuki.php?" ascii //weight: 4
        $x_4_2 = "http://stomachgrape.xyz/kukis.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_OffLoader_ZZV_2147958880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZZV!MTB"
        threat_id = "2147958880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://rabbithoney.info/arki.php?" ascii //weight: 4
        $x_4_2 = "://baseballafternoon.xyz/arkis.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_SPLE_2147958987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.SPLE!MTB"
        threat_id = "2147958987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "discoverytrucks.info/gant.php" wide //weight: 2
        $x_1_2 = "Do you want to reboot now?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AWMB_2147959140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AWMB!MTB"
        threat_id = "2147959140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://rootsystem.info/done.php?" ascii //weight: 4
        $x_4_2 = "://monthaunt.xyz/dones.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZCI_2147959223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZCI!MTB"
        threat_id = "2147959223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://inventionplastic.xyz/milts.php?" ascii //weight: 3
        $x_3_2 = "://bookserror.info/milt.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_ZFI_2147959332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.ZFI!MTB"
        threat_id = "2147959332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "://seedrub.xyz/ujjts.php?" ascii //weight: 3
        $x_3_2 = "://losstwig.info/ujjt.php?" ascii //weight: 3
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_OffLoader_AENB_2147959458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OffLoader.AENB!MTB"
        threat_id = "2147959458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OffLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://instrumentthrone.info/miju.php?" ascii //weight: 4
        $x_4_2 = "://bottlegrain.xyz/mijus.php?" ascii //weight: 4
        $x_1_3 = "/silent" ascii //weight: 1
        $x_1_4 = "Do you want to reboot now?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

