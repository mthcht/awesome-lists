rule Trojan_MSIL_SnakeStealerldr_MK_2147772759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeStealerldr.MK!MTB"
        threat_id = "2147772759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeStealerldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AMe8.dll" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "GetHashCode" ascii //weight: 1
        $x_1_4 = {41 4d 65 38 2e 4d 79 [0-255] 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 74 74 69 6e 67 73 42 61 73 65}  //weight: 1, accuracy: Low
        $x_1_5 = "SpecialFolder" ascii //weight: 1
        $x_1_6 = "MulticastDelegate" ascii //weight: 1
        $x_1_7 = "BeginInvoke" ascii //weight: 1
        $x_1_8 = "DelegateCallback" ascii //weight: 1
        $x_1_9 = "EndInvoke" ascii //weight: 1
        $x_1_10 = "DelegateAsyncResult" ascii //weight: 1
        $x_1_11 = "ProcessBasicInformation" ascii //weight: 1
        $x_1_12 = "ProcessWow64Information" ascii //weight: 1
        $x_1_13 = "CreateProcessAsUser" ascii //weight: 1
        $x_1_14 = "PasswordDeriveBytes" ascii //weight: 1
        $x_1_15 = "AMe8.Resources.resources" ascii //weight: 1
        $x_1_16 = "BlockCopy" ascii //weight: 1
        $x_1_17 = "get_CurrentDomain" ascii //weight: 1
        $x_1_18 = "add_AssemblyResolve" ascii //weight: 1
        $x_1_19 = "get_Value" ascii //weight: 1
        $x_1_20 = "set_Value" ascii //weight: 1
        $x_1_21 = "get_Assembly" ascii //weight: 1
        $x_1_22 = "ProjectData" ascii //weight: 1
        $x_1_23 = "get_BaseAddress" ascii //weight: 1
        $x_1_24 = "get_Unicode" ascii //weight: 1
        $x_1_25 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

