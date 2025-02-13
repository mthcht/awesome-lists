rule PWS_Win32_Azurlt_2147766724_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Azurlt!MTB"
        threat_id = "2147766724"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Azurlt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxs" ascii //weight: 1
        $x_1_2 = "InternetSetOptionA" ascii //weight: 1
        $x_1_3 = "RegCreateKeyExW" ascii //weight: 1
        $x_1_4 = "SetEnvironmentVariableW" ascii //weight: 1
        $x_1_5 = "CreateProcessAsUserW" ascii //weight: 1
        $x_1_6 = "GlobalMemoryStatus" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "GdipGetImageEncodersSize" ascii //weight: 1
        $x_1_9 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA==" ascii //weight: 1
        $x_1_10 = "GDIScreenShot" ascii //weight: 1
        $x_1_11 = "CryptReleaseContext" ascii //weight: 1
        $x_1_12 = "CryptUnprotectData" ascii //weight: 1
        $x_1_13 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_14 = "PVAULT_CRED8" ascii //weight: 1
        $x_1_15 = "Process32NextW" ascii //weight: 1
        $x_1_16 = "uFileFinderU" ascii //weight: 1
        $x_1_17 = "uIE7_decodeU" ascii //weight: 1
        $x_1_18 = "PasswordsList.txt" ascii //weight: 1
        $x_1_19 = "ShellExecuteExW" ascii //weight: 1
        $x_1_20 = "GetLogicalDriveStringsA" ascii //weight: 1
        $x_1_21 = "InternetReadFile" ascii //weight: 1
        $x_1_22 = "HttpSendRequestA" ascii //weight: 1
        $x_1_23 = "InternetCrackUrlA" ascii //weight: 1
        $x_1_24 = "HttpAddRequestHeadersA" ascii //weight: 1
        $x_1_25 = "Browsers\\Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

