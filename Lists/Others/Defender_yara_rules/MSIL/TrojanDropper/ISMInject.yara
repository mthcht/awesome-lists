rule TrojanDropper_MSIL_ISMInject_A_2147727321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/ISMInject.A!dha"
        threat_id = "2147727321"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ISMInject"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" wide //weight: 1
        $x_1_2 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_3 = "aspnet_wp.exe" wide //weight: 1
        $x_1_4 = "w3wp.exe" wide //weight: 1
        $x_1_5 = "srvBS.txt" wide //weight: 1
        $x_1_6 = "SrvHealth.exe" wide //weight: 1
        $x_1_7 = "PolicyConvertor" wide //weight: 1
        $x_1_8 = "PolicyConverter.Resources" wide //weight: 1
        $x_1_9 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" wide //weight: 1
        $x_1_10 = "Tsk1" wide //weight: 1
        $x_1_11 = "Tsk2" wide //weight: 1
        $x_1_12 = "cmd.exe /c " wide //weight: 1
        $x_1_13 = "{0}{1}\\" wide //weight: 1
        $x_1_14 = "Wrong Header Signature" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

