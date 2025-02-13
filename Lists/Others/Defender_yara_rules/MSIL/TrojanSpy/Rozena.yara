rule TrojanSpy_MSIL_Rozena_MA_2147809188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Rozena.MA!MTB"
        threat_id = "2147809188"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TyIpDQp9DQo=" wide //weight: 1
        $x_1_2 = "-whatt" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "-extdummt" wide //weight: 1
        $x_1_5 = "-debug" wide //weight: 1
        $x_1_6 = "-zzxtract" wide //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_9 = "PromptForPassword" ascii //weight: 1
        $x_1_10 = "getPassword" ascii //weight: 1
        $x_1_11 = "GetCharFromKeys" ascii //weight: 1
        $x_1_12 = "Credential_Form" ascii //weight: 1
        $x_1_13 = "Keyboard_Form_KeyUp" ascii //weight: 1
        $x_1_14 = "set_VirtualKeyCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

