rule Trojan_Win32_CmdFromRemoteDroppedSvc_A_2147776201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CmdFromRemoteDroppedSvc.A"
        threat_id = "2147776201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CmdFromRemoteDroppedSvc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-80] 63 00 6f 00 70 00 79 00 20 00 [0-16] 5c 00 5c 00}  //weight: 1, accuracy: Low
        $n_10_2 = "sysvol" wide //weight: -10
        $n_10_3 = "\\Altea" wide //weight: -10
        $n_10_4 = "\\tdsbresource" wide //weight: -10
        $n_10_5 = "\\BoardMaker Studio" wide //weight: -10
        $n_10_6 = "webextract" wide //weight: -10
        $n_10_7 = "jbaconsulting" wide //weight: -10
        $n_10_8 = "syngentaazure" wide //weight: -10
        $n_10_9 = "deployment" wide //weight: -10
        $n_10_10 = "balgroupit.com" wide //weight: -10
        $n_10_11 = "^& IF %ERRORLEVEL% LEQ 1 exit 0" wide //weight: -10
        $n_10_12 = {72 00 6f 00 62 00 6f 00 63 00 6f 00 70 00 79 00 [0-240] 6d 00 69 00 72 00}  //weight: -10, accuracy: Low
        $n_10_13 = {78 00 63 00 6f 00 70 00 79 00 [0-240] 2f 00 65 00 2f 00 66 00 2f 00 64 00 2f 00 69 00 2f 00 73 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_CmdFromRemoteDroppedSvc_B_2147776202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CmdFromRemoteDroppedSvc.B"
        threat_id = "2147776202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CmdFromRemoteDroppedSvc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 [0-48] 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-80] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $n_10_2 = "Movere" wide //weight: -10
        $n_10_3 = "frameworkverifier" wide //weight: -10
        $n_10_4 = "Acronis" wide //weight: -10
        $n_10_5 = "deployment" wide //weight: -10
        $n_10_6 = "staging" wide //weight: -10
        $n_10_7 = "collectionengine" wide //weight: -10
        $n_10_8 = "PANFT" wide //weight: -10
        $n_10_9 = "temp\\unzip" wide //weight: -10
        $n_10_10 = "OT_IC_Client\\7za" wide //weight: -10
        $n_10_11 = "\\azure" wide //weight: -10
        $n_10_12 = "opentext" wide //weight: -10
        $n_10_13 = "-uninstall" wide //weight: -10
        $n_10_14 = "ccmsetup" wide //weight: -10
        $n_10_15 = "windows\\ccm" wide //weight: -10
        $n_10_16 = "crystalreport" wide //weight: -10
        $n_10_17 = {63 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 65 00 6e 00 67 00 69 00 6e 00 65 00 [0-128] 74 00 61 00 64 00 64 00 6d 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_CmdFromRemoteDroppedSvc_C_2147799131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CmdFromRemoteDroppedSvc.C"
        threat_id = "2147799131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CmdFromRemoteDroppedSvc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 [0-80] 70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 [0-80] 70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

