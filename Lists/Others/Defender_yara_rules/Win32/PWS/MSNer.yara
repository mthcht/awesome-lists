rule PWS_Win32_MSNer_A_2147648054_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/MSNer.A"
        threat_id = "2147648054"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "MSNer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TLiveMessenger" wide //weight: 1
        $x_1_2 = "notepad\\secret.datt" ascii //weight: 1
        $x_1_3 = "taskkill /im msnmsgr.exe /f" ascii //weight: 1
        $x_1_4 = "wagnermi22.com/enviador.php" wide //weight: 1
        $x_1_5 = "3rdparty\\ScreamSec\\SecUtils.pas" ascii //weight: 1
        $x_1_6 = "SYSTEM\\CurrentControlSet\\Services\\NTice\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

