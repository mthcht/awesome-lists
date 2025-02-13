rule Constructor_Win32_Vbsgen_A_2147643227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Vbsgen.A"
        threat_id = "2147643227"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbsgen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Vbs Virus Generator" ascii //weight: 2
        $x_1_2 = "Set DiskCopy =Fso.CreateTextFile(Drive.DriveLetter &" wide //weight: 1
        $x_1_3 = "Function SendPost(strSMTP_Server, strTo, strFrom, strSubject, strBody)" wide //weight: 1
        $x_1_4 = "wshl.RegWrite HKCUrun1 & HKLMrun1 & HKLMrun2 & HKLMrun3 & HKCUrun5" wide //weight: 1
        $x_1_5 = "strFolder =Dri.DriveLetter &" wide //weight: 1
        $x_1_6 = "IE.AddressBar = False" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

