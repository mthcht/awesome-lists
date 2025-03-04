rule Trojan_MSIL_Fakesupport_DA_2147841593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fakesupport.DA!MTB"
        threat_id = "2147841593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fakesupport"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 11 05 28 ?? 00 00 0a 13 06 02 11 06 28 ?? 00 00 06 00 00 de 0d 11 04 2c 08 11 04 6f ?? 00 00 0a 00 dc}  //weight: 2, accuracy: Low
        $x_1_2 = "tawk.to/chat/5d747ea2eb1a6b0be60b89c7/default" wide //weight: 1
        $x_1_3 = "WinPop.Properties.Resources" wide //weight: 1
        $x_1_4 = "Select * FROM Win32_NetworkAdapterConfiguration" wide //weight: 1
        $x_1_5 = "WindowsUpdate.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

