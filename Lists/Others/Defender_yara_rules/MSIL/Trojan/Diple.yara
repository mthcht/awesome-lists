rule Trojan_MSIL_Diple_RDA_2147834658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diple.RDA!MTB"
        threat_id = "2147834658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diple"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8351fb32-4643-4b0a-a4f6-c3d4bce87341" ascii //weight: 1
        $x_1_2 = "C:\\windows\\system32\\mstsc.exe" ascii //weight: 1
        $x_1_3 = "mstscax.dll" wide //weight: 1
        $x_1_4 = "MSTSCDLLSideLoading" ascii //weight: 1
        $x_1_5 = "Select * From Win32_Process Where ProcessID =" wide //weight: 1
        $x_1_6 = "SELECT CommandLine FROM Win32_Process WHERE ProcessId =" wide //weight: 1
        $x_1_7 = "Global\\CYMULATE_EDR_" ascii //weight: 1
        $x_1_8 = "wmic path win32_utctime get /format:list ^| findstr \"=\"" wide //weight: 1
        $x_1_9 = "kernel32.dll" ascii //weight: 1
        $x_1_10 = "FindResourceW" ascii //weight: 1
        $x_1_11 = "LoadResource" ascii //weight: 1
        $x_1_12 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
        $x_1_13 = "DropMaliciousDLL" wide //weight: 1
        $x_1_14 = "GetMSTSC" wide //weight: 1
        $x_1_15 = "StartMSTSC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

