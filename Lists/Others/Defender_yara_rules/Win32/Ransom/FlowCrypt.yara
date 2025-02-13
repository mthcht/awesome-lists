rule Ransom_Win32_FlowCrypt_AA_2147758603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FlowCrypt.AA!MTB"
        threat_id = "2147758603"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FlowCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".flowCRYPTED" wide //weight: 1
        $x_1_2 = "$DRIVES = DRIVEGETDRIVE ( $DT_REMOVABLE )" wide //weight: 1
        $x_1_3 = "GETFILESTOCRYPT ( @USERPROFILEDIR " wide //weight: 1
        $x_1_4 = "GETFILESTOCRYPT ( $DRIVESFOUNDED " wide //weight: 1
        $x_1_5 = "= _CRYPT_DECRYPTDATA ( $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

