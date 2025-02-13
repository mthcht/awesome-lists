rule Trojan_Win32_Rofin_A_2147684415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.A"
        threat_id = "2147684415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "multi\\Release\\multi.pdb" ascii //weight: 1
        $x_1_2 = "miniie" ascii //weight: 1
        $x_5_3 = "sogou.com/?71017-0001" ascii //weight: 5
        $x_1_4 = "{9A4DDA61-1D3A-49B7-9849-DAC6CD30A393}" ascii //weight: 1
        $x_5_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c [0-3] 2e 69 6e 69}  //weight: 5, accuracy: Low
        $x_1_6 = "DProEx.sys" ascii //weight: 1
        $x_1_7 = "run.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rofin_A_2147684415_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.A"
        threat_id = "2147684415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "log.soomeng.com" ascii //weight: 5
        $x_5_2 = "log.zzinfor.cn" ascii //weight: 5
        $x_5_3 = "115.238.251.56" ascii //weight: 5
        $x_1_4 = "{4D36E972-E325-11CE-BFC1-08002BE10318}" ascii //weight: 1
        $x_1_5 = "'bdgngodom';" ascii //weight: 1
        $x_1_6 = "c:\\tao.html" ascii //weight: 1
        $x_1_7 = "C:\\Windows\\System32\\blk.ini" ascii //weight: 1
        $x_1_8 = "sogou.com/?71017-0001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rofin_A_2147684415_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.A"
        threat_id = "2147684415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\SSDTProcess" ascii //weight: 1
        $x_1_2 = "HideSys.sys" ascii //weight: 1
        $x_1_3 = "%04d%02d%02d%02d%02d%02d%03d" ascii //weight: 1
        $x_1_4 = "flist.bin" ascii //weight: 1
        $x_1_5 = "/plus/config/" ascii //weight: 1
        $x_1_6 = "StartService~ %08x" ascii //weight: 1
        $x_1_7 = "115.238.251.56" ascii //weight: 1
        $x_1_8 = "log.soomeng.com" ascii //weight: 1
        $x_1_9 = "www.4278.cn" ascii //weight: 1
        $x_1_10 = "log.zzinfor.cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Rofin_B_2147691135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.B"
        threat_id = "2147691135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MOUSEHOOK.DLL" wide //weight: 1
        $x_1_2 = "EyooSechelper2.dll" wide //weight: 1
        $x_1_3 = "bsooa.dll" wide //weight: 1
        $x_1_4 = "Desktophook.dll" wide //weight: 1
        $x_1_5 = "fakeUrl:" ascii //weight: 1
        $x_1_6 = "taskkill /pid %d" ascii //weight: 1
        $x_1_7 = "\\\\.\\FixTool" ascii //weight: 1
        $x_1_8 = "TOMMAO.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Rofin_B_2147691135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.B"
        threat_id = "2147691135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#DRVDIR#ZWebNds.sys" ascii //weight: 1
        $x_1_2 = "#F001#" ascii //weight: 1
        $x_1_3 = "c:/windows/ax01.da0" ascii //weight: 1
        $x_1_4 = "uniconfi.dat" ascii //weight: 1
        $x_1_5 = "{A09A01FF-1DBC-400C-8132-54FA4DBE4E96};{524F94CD-71CB-4CCD-81B1-58F4F6F51BFF};" ascii //weight: 1
        $x_1_6 = "http://log.soomeng.com/wb/jdq/?mac=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rofin_C_2147709389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rofin.C!bit"
        threat_id = "2147709389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofin"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ad.zzinfor.cn/static/hotkey.txt" ascii //weight: 10
        $x_1_2 = "f1browser.exe" ascii //weight: 1
        $x_1_3 = "csc3-2010" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\Env.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

