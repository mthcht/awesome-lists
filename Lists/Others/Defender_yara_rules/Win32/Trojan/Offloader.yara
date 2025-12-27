rule Trojan_Win32_Offloader_CC_2147850814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CC!MTB"
        threat_id = "2147850814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 79 00 65 00 61 00 72 00 63 00 6f 00 61 00 6c 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 66 00 61 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CD_2147850815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CD!MTB"
        threat_id = "2147850815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 63 00 74 00 2e 00 72 00 65 00 61 00 63 00 74 00 69 00 6f 00 6e 00 68 00 61 00 72 00 62 00 6f 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 6c 00 6f 00 67 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CE_2147851027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CE!MTB"
        threat_id = "2147851027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 61 00 76 00 65 00 2e 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 73 00 6f 00 6e 00 67 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 61 00 70 00 69 00 5f 00 70 00 65 00 6c 00 6f 00 67 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CF_2147851183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CF!MTB"
        threat_id = "2147851183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 6c 00 6f 00 63 00 6b 00 73 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 73 00 69 00 74 00 65 00 2f 00 65 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 70}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CG_2147852048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CG!MTB"
        threat_id = "2147852048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 69 00 74 00 2e 00 73 00 65 00 61 00 74 00 66 00 6c 00 6f 00 63 00 6b 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 64 00 72 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBA_2147891228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBA!MTB"
        threat_id = "2147891228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 75 00 6d 00 6d 00 65 00 72 00 70 00 65 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBB_2147891234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBB!MTB"
        threat_id = "2147891234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 65 00 73 00 6b 00 73 00 65 00 61 00 73 00 68 00 6f 00 72 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 77 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBN_2147891776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBN!MTB"
        threat_id = "2147891776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 00 72 00 79 00 2e 00 6d 00 69 00 73 00 74 00 66 00 6c 00 6f 00 63 00 6b 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 73 00 73 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBO_2147891777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBO!MTB"
        threat_id = "2147891777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 00 69 00 70 00 73 00 70 00 61 00 72 00 6b 00 2e 00 73 00 69 00 74 00 65 00 2f 00 68 00 75 00 72 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBS_2147891934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBS!MTB"
        threat_id = "2147891934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 00 65 00 65 00 73 00 65 00 71 00 75 00 69 00 6c 00 74 00 2e 00 78 00 79 00 7a 00 2f 00 65 00 61 00 74 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCBU_2147892039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCBU!MTB"
        threat_id = "2147892039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 00 61 00 67 00 65 00 63 00 65 00 6c 00 6c 00 61 00 72 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 64 00 75 00 6e 00 6b 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCCN_2147892952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCCN!MTB"
        threat_id = "2147892952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 69 00 6b 00 65 00 69 00 6d 00 70 00 75 00 6c 00 73 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 74 00 69 00 2e 00 70 00 68 00 70 00 3f}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_AMBC_2147898882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.AMBC!MTB"
        threat_id = "2147898882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://shopbead.online/bart.php" ascii //weight: 2
        $x_2_2 = "://smellcircle.site/tracker/thank_you.php" ascii //weight: 2
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_AMBC_2147898882_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.AMBC!MTB"
        threat_id = "2147898882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://clamwire.xyz/ch.php" wide //weight: 2
        $x_2_2 = "http://recessorange.xyz/ch.php" wide //weight: 2
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_AMBI_2147900082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.AMBI!MTB"
        threat_id = "2147900082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://crowncast.website/in.php" wide //weight: 5
        $x_5_2 = "http://knifesense.website/api_pedl.php" wide //weight: 5
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Offloader_AMAF_2147900870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.AMAF!MTB"
        threat_id = "2147900870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 68 00 65 00 6f 00 72 00 79 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6c 00 61 00 6d 00 2e 00 70 00 68 00 70}  //weight: 5, accuracy: High
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 72 00 69 00 64 00 64 00 6c 00 65 00 63 00 61 00 72 00 72 00 69 00 61 00 67 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6c 00 61 00 6d 00 2e 00 70 00 68 00 70}  //weight: 5, accuracy: High
        $x_1_3 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "restart the computer now" wide //weight: 1
        $x_1_5 = "Yes, I would like to view the README file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Offloader_GZM_2147901758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.GZM!MTB"
        threat_id = "2147901758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://brassforce.site/ploss.php" ascii //weight: 2
        $x_2_2 = "goo.gl/fxTiKZ" ascii //weight: 2
        $x_1_3 = "only/ppba" ascii //weight: 1
        $x_1_4 = "Software\\sdfwsdfs6df" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCHL_2147902065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCHL!MTB"
        threat_id = "2147902065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "clambirth.site/ball.php?" ascii //weight: 5
        $x_5_2 = "bookapparatus.online/tracker/thank_you.php?" ascii //weight: 5
        $x_5_3 = "committeeoffer.website/all.php?" ascii //weight: 5
        $x_5_4 = "viewcloth.online/tracker/thank_you.php?" ascii //weight: 5
        $x_5_5 = "jamcabbage.online/thankyou.php?" ascii //weight: 5
        $x_1_6 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Offloader_B_2147902780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.B!MTB"
        threat_id = "2147902780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://woodlevel.site/tracker/thank_you.php?" wide //weight: 2
        $x_2_2 = "://vestmountain.site/bli.php?" wide //weight: 2
        $x_1_3 = "/silent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_GZK_2147903164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.GZK!MTB"
        threat_id = "2147903164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sto.farmscene.website" wide //weight: 2
        $x_2_2 = {00 68 00 75 00 6d 00 6f 00 72 00 73 00 63 00 69 00 65 00 6e 00 63 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 61 00 73 00 69 00 6b 00 6f 00 2e 00 70 00 68 00 70}  //weight: 2, accuracy: High
        $x_1_3 = "only/ppba" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_C_2147903565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.C!MTB"
        threat_id = "2147903565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://pleasurefly.online/tracker/thank_you.php?" wide //weight: 2
        $x_2_2 = "://languagebone.online/goto.php?" wide //weight: 2
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAA_2147903577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAA!MTB"
        threat_id = "2147903577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://sinkline.xyz/lmk.php" ascii //weight: 2
        $x_2_2 = "://save.windowstone.website" ascii //weight: 2
        $x_1_3 = "Software\\SPoloCleaner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_D_2147903714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.D!MTB"
        threat_id = "2147903714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://sinkline.xyz/lmk.php?" wide //weight: 2
        $x_2_2 = ".xyz/lok.php?" wide //weight: 2
        $x_2_3 = "--silent --allusers=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_CCHW_2147905100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.CCHW!MTB"
        threat_id = "2147905100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scienceeducation.online/ir/sreb.php?" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
        $x_1_3 = "run.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_E_2147905719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.E!MTB"
        threat_id = "2147905719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/SILENT, /VERYSILENT" wide //weight: 2
        $x_2_2 = "/SUPPRESSMSGBOXES" wide //weight: 2
        $x_2_3 = "://pp.toothbrushindustry.online/track_" wide //weight: 2
        $x_2_4 = ".website/ss.php?pid=" wide //weight: 2
        $x_2_5 = "{tmp}\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAB_2147906594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAB!MTB"
        threat_id = "2147906594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://bagoffer.site" ascii //weight: 2
        $x_2_2 = "://notefriends.site/bch.php" ascii //weight: 2
        $x_1_3 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_F_2147906952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.F!MTB"
        threat_id = "2147906952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tracker/thank_you.php?trk=" wide //weight: 2
        $x_2_2 = "://goal.harborhorse.online/track_" wide //weight: 2
        $x_2_3 = "wee.php?pid=" wide //weight: 2
        $x_2_4 = "{tmp}\\check" wide //weight: 2
        $x_2_5 = "/VERYSILENT" wide //weight: 2
        $x_2_6 = "/SUPPRESSMSGBOXES" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAC_2147907078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAC!MTB"
        threat_id = "2147907078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://beadobservation.site/rlo.php" ascii //weight: 2
        $x_2_2 = "VERYSILENT /SUPPRESSMSGBOXES" ascii //weight: 2
        $x_1_3 = "only/ppba" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_G_2147907695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.G!MTB"
        threat_id = "2147907695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e/llo.php?paw=" wide //weight: 2
        $x_2_2 = "goal.harborhorse.online/track_" wide //weight: 2
        $x_2_3 = "e/rlo.php?fz=" wide //weight: 2
        $x_2_4 = "{tmp}\\check" wide //weight: 2
        $x_2_5 = "/VERYSILENT" wide //weight: 2
        $x_2_6 = "/SUPPRESSMSGBOXES" wide //weight: 2
        $x_2_7 = "e/tracker/thank_you.php?trk=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_H_2147907871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.H!MTB"
        threat_id = "2147907871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".online/tracker/thank_you.php?trk=" wide //weight: 2
        $x_2_2 = ".online/llo.php?paw=" wide //weight: 2
        $x_2_3 = ".online/rlo.php?fz=" wide //weight: 2
        $x_2_4 = "{tmp}\\check" wide //weight: 2
        $x_2_5 = "/VERYSILENT" wide //weight: 2
        $x_2_6 = "/SUPPRESSMSGBOXES" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_I_2147909877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.I!MTB"
        threat_id = "2147909877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/sdf.php?pid=" wide //weight: 2
        $x_2_2 = "/yet.php?paw=" wide //weight: 2
        $x_2_3 = "/rlo.php?d=" wide //weight: 2
        $x_2_4 = "://goal.harborhorse.online/track_bro.php?tim=" wide //weight: 2
        $x_2_5 = "://goal.harborhorse.online/track_polosWW.php?tim=" wide //weight: 2
        $x_2_6 = "/tracker/thank_you.php?trk=" wide //weight: 2
        $x_2_7 = "{tmp}\\check" wide //weight: 2
        $x_2_8 = "/VERYSILENT" wide //weight: 2
        $x_2_9 = "/SUPPRESSMSGBOXES" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_J_2147909973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.J!MTB"
        threat_id = "2147909973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".online/rlo.php?fz=" wide //weight: 2
        $x_2_2 = ".online/tracker/thank_you.php?trk=" wide //weight: 2
        $x_2_3 = "://goal.harborhorse.online/track_polosEU.php?tim=" wide //weight: 2
        $x_2_4 = "://goal.harborhorse.online/track_ukiEU.php?tim=" wide //weight: 2
        $x_2_5 = "{tmp}\\check" wide //weight: 2
        $x_2_6 = "/VERYSILENT" wide //weight: 2
        $x_2_7 = "/SUPPRESSMSGBOXES" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_K_2147910481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.K!MTB"
        threat_id = "2147910481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/VERYSILENT" wide //weight: 2
        $x_2_2 = "/SUPPRESSMSGBOXES" wide //weight: 2
        $x_2_3 = "{tmp}\\check" wide //weight: 2
        $x_2_4 = "/sdf.php?pid=" wide //weight: 2
        $x_2_5 = "/tracker/thank_you.php?trk=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAD_2147910573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAD!MTB"
        threat_id = "2147910573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://toothpastethings.xyz/yas.php" ascii //weight: 2
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_L_2147911858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.L!MTB"
        threat_id = "2147911858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/VERYSILENT" wide //weight: 2
        $x_2_2 = "/SUPPRESSMSGBOXES" wide //weight: 2
        $x_2_3 = "{tmp}\\check" wide //weight: 2
        $x_2_4 = "/rlo.php?fz=" wide //weight: 2
        $x_2_5 = "/yet.php?paw=" wide //weight: 2
        $x_2_6 = "/tracker/thank_you.php?trk=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAE_2147912428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAE!MTB"
        threat_id = "2147912428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/birthghost.icu/wind.php" ascii //weight: 5
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAF_2147915325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAF!MTB"
        threat_id = "2147915325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/quicksandshape.icu/itis.php" ascii //weight: 5
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAG_2147916226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAG!MTB"
        threat_id = "2147916226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/snakesbait.icu" ascii //weight: 5
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAH_2147916927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAH!MTB"
        threat_id = "2147916927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/flagcrow.icu" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAI_2147917386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAI!MTB"
        threat_id = "2147917386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/steelteam.xyz" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAJ_2147917720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAJ!MTB"
        threat_id = "2147917720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lacebit.xyz" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAK_2147919631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAK!MTB"
        threat_id = "2147919631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/roadlow.icu" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAL_2147920528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAL!MTB"
        threat_id = "2147920528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/achieverart.space/ist.php" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAM_2147921802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAM!MTB"
        threat_id = "2147921802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/theoryquarter.cfd/hul.php" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAO_2147922349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAO!MTB"
        threat_id = "2147922349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "doctorframe.sbs/anj.php" ascii //weight: 1
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_AMS_2147924126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.AMS!MTB"
        threat_id = "2147924126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://voicecarriage.website/kam.php" ascii //weight: 4
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_GPN_2147924802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.GPN!MTB"
        threat_id = "2147924802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dirtinstrument.xyz/pe/build.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAP_2147925316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAP!MTB"
        threat_id = "2147925316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/playgroundstone.cfd/jui.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAR_2147925823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAR!MTB"
        threat_id = "2147925823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/washlumber.icu/mpt.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAS_2147927986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAS!MTB"
        threat_id = "2147927986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/biteducks.sbs/bea.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAT_2147928967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAT!MTB"
        threat_id = "2147928967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/lumbercare.sbs/car.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAU_2147929092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAU!MTB"
        threat_id = "2147929092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/trucksstick.icu/don.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAV_2147929347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAV!MTB"
        threat_id = "2147929347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/dogdecision.cfd/bar.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_KAW_2147929774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.KAW!MTB"
        threat_id = "2147929774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/shademom.icu/n25.php" ascii //weight: 10
        $x_1_2 = "/silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Offloader_GKP_2147947399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offloader.GKP!MTB"
        threat_id = "2147947399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b2 35 00 ?? ?? ?? ?? be 41 0e 00 00 e4 0c 00 ?? ?? ?? ?? 00 00 01 00 0d 00 40 40}  //weight: 4, accuracy: Low
        $x_4_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 60 33 00 ?? ?? ?? ?? 3a 46 0e 00 00 e8 0c 00 ?? ?? ?? ?? 00 00 01 00 0d 00 40 40}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

