rule Trojan_Win32_CoronaVirus_V_2147751461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoronaVirus.V!MTB"
        threat_id = "2147751461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoronaVirus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c rd/s /q c:\\" wide //weight: 1
        $x_1_2 = "cmd /c REG DELETE HKLM\\Software\\ /f" wide //weight: 1
        $x_1_3 = "cmd /c rd/s /q d:\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoronaVirus_A_2147954079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoronaVirus.A"
        threat_id = "2147954079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoronaVirus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add " ascii //weight: 1
        $x_1_2 = "autocheck autochk *" ascii //weight: 1
        $x_1_3 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" ascii //weight: 1
        $x_1_4 = "BootExecute" ascii //weight: 1
        $x_1_5 = " /t REG_MULTI_SZ /F /D " ascii //weight: 1
        $x_1_6 = " /V " wide //weight: 1
        $n_1_7 = "9453e881-26a8-4973-ba2e-76269e901d0n" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_CoronaVirus_B_2147954080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoronaVirus.B"
        threat_id = "2147954080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoronaVirus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c for %G in " ascii //weight: 1
        $x_1_2 = "(.bak, .bat, .doc, .jpg, .jpe, .txt, .tex," ascii //weight: 1
        $x_1_3 = ".dbf, .xls, .cry, .xml, .vsd, .pdf, .csv, .bmp," ascii //weight: 1
        $x_1_4 = ".tif, .tax, .gif, .gbr, .png, .mdb, .mdf," ascii //weight: 1
        $x_1_5 = ".sdf, .dwg, .dxf, .dgn, .stl, .gho, .ppt, .acc," ascii //weight: 1
        $x_1_6 = ".vpd, .odt, .ods, .rar, .zip, .cpp, .pas," ascii //weight: 1
        $x_1_7 = ".asm, .rtf, .lic, .avi, .mov, .vbs, .erf," ascii //weight: 1
        $x_1_8 = ".epf, .mxl, .cfu, .mht, .bak, .old)" ascii //weight: 1
        $x_1_9 = "do forfiles /p " ascii //weight: 1
        $x_1_10 = " /s /M *%G /C " ascii //weight: 1
        $x_1_11 = "cmd /c echo @PATH" ascii //weight: 1
        $n_1_12 = "9453e881-26a8-4973-ba2e-76269e901d0o" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

