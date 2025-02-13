rule Ransom_MSIL_Hakbit_F_2147753699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hakbit.F!MTB"
        threat_id = "2147753699"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hakbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FTP Password" wide //weight: 1
        $x_1_2 = "<Killproc>" ascii //weight: 1
        $x_1_3 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24=" wide //weight: 1
        $x_1_4 = "QXRlbnRpb24uLi4=" wide //weight: 1
        $x_1_5 = "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQsIGlmIHlvdSB3YW50IHRvIGdldCB0aGVtIGFsbCBiYWNrLCBwb" wide //weight: 1
        $x_1_6 = "GVhc2UgY2FyZWZ1bGx5IHJlYWQgdGhlIHRleHQgbm90ZSBsb2NhdGVkIGluIHlvdXIgZGVza3RvcC4uLg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Hakbit_SK_2147753710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hakbit.SK!MTB"
        threat_id = "2147753710"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hakbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\HELP_ME_RECOVER_MY_FILES.txt" wide //weight: 10
        $x_10_2 = "\\DEAL_FOR_ACCESS_TO_YOUR_FILES.txt" wide //weight: 10
        $x_10_3 = "http://www.my_wallpaper_location.com/wallpaper.bmp" wide //weight: 10
        $x_10_4 = "RansomBuilder_Log" wide //weight: 10
        $x_10_5 = "RGF0ZSBvZiBlbmNyeXB0aW9uOiA=" wide //weight: 10
        $x_10_6 = "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" wide //weight: 10
        $x_15_7 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24=" wide //weight: 15
        $x_15_8 = "QXRlbnRpb24" wide //weight: 15
        $x_15_9 = "U2V0LU1wUHJlZmVyZW5jZSAtRW5hYmxlQ29udHJvbGxlZEZvbGRlckFjY2VzcyBEaXNhYmxlZA==" wide //weight: 15
        $x_2_10 = "net.exe" wide //weight: 2
        $x_2_11 = "sc.exe" wide //weight: 2
        $x_2_12 = "vssadmin.exe" wide //weight: 2
        $x_2_13 = "taskkill.exe" wide //weight: 2
        $x_2_14 = "del.exe" wide //weight: 2
        $x_5_15 = "ftp://files.000webhost.com/public_html/" wide //weight: 5
        $x_5_16 = "FTP UserName" wide //weight: 5
        $x_5_17 = "FTP Password" wide //weight: 5
        $x_5_18 = "ACCESS" wide //weight: 5
        $x_1_19 = "AesManaged" ascii //weight: 1
        $x_1_20 = "UploadFile" ascii //weight: 1
        $x_1_21 = "FtpWebResponse" ascii //weight: 1
        $x_1_22 = "ToBase64String" ascii //weight: 1
        $x_1_23 = "RtlSetProcessIsCritical" ascii //weight: 1
        $x_1_24 = "SHEmptyRecycleBin" ascii //weight: 1
        $x_1_25 = "FileInfo" ascii //weight: 1
        $x_1_26 = "DriveInfo" ascii //weight: 1
        $x_1_27 = "FileSystemInfo" ascii //weight: 1
        $x_1_28 = "SmartAssembly" ascii //weight: 1
        $x_1_29 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_5_*) and 11 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_10_*))) or
            ((1 of ($x_15_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((2 of ($x_15_*) and 1 of ($x_1_*))) or
            ((2 of ($x_15_*) and 1 of ($x_2_*))) or
            ((2 of ($x_15_*) and 1 of ($x_5_*))) or
            ((2 of ($x_15_*) and 1 of ($x_10_*))) or
            ((3 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Hakbit_HZ_2147755083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hakbit.HZ!MTB"
        threat_id = "2147755083"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hakbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Killproc>" ascii //weight: 1
        $x_1_2 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "b732058@noether-stiftung.de" wide //weight: 1
        $x_1_4 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24=" wide //weight: 1
        $x_1_5 = "QXRlbnRpb24uLi4=" wide //weight: 1
        $x_1_6 = "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQsIGlmIHlvdSB3YW50IHRvIGdldCB0aGVtIGFsbCBiYWNrLCBwb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Hakbit_PA_2147771605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hakbit.PA!MTB"
        threat_id = "2147771605"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hakbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide //weight: 1
        $x_1_2 = ".energy[potentialenergy@mail.ru]" wide //weight: 1
        $x_1_3 = "\\HOW_TO_DECYPHER_FILES.txt" wide //weight: 1
        $x_1_4 = "\\HOW_TO_DECYPHER_FILES.hta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

