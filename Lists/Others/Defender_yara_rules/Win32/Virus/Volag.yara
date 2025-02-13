rule Virus_Win32_Volag_E_2147598874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Volag.E"
        threat_id = "2147598874"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Volag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Win32.Voltage Virus Written By DR-EF (c) 2004" ascii //weight: 1
        $x_1_2 = "ReadMe.exe" ascii //weight: 1
        $x_1_3 = "DIRS\\BOX\\W32_VOLTAGE.EXE" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\SYSTEM\\wvltg.exe" ascii //weight: 1
        $x_1_5 = "MAIL FROM:<SecurityUpdate@Microsoft.com>" ascii //weight: 1
        $x_1_6 = "MAIL FROM:<FreePictures@WorldSex.com>" ascii //weight: 1
        $x_1_7 = "MAIL FROM:<VirusAlert@Symantec.com>" ascii //weight: 1
        $x_1_8 = "MAIL FROM:<Support@Kazaa.com>" ascii //weight: 1
        $x_1_9 = "MAIL FROM:<Greets@Greeting-Cards.com>" ascii //weight: 1
        $x_1_10 = "filename= \"150_XXX_Pictures.exe\"" ascii //weight: 1
        $x_1_11 = "Dear Symantec/F-Secure/Mcafee/Trend Micro User" ascii //weight: 1
        $x_1_12 = "filename= \"Kazaa Media Desktop.exe\"" ascii //weight: 1
        $x_1_13 = "Greeting-Cards.com have sent you a Greeting Card" ascii //weight: 1
        $x_1_14 = "filename= \"Your Greeting Card.exe\"" ascii //weight: 1
        $x_1_15 = "Software\\Microsoft\\WAB\\WAB4\\Wab File Name" ascii //weight: 1
        $x_1_16 = "f-tbawantizonescanprotmonirwebmircckdotrojsafejeditrayandainocspidplorndlltrenamonnsplnschnod3alersmssh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

