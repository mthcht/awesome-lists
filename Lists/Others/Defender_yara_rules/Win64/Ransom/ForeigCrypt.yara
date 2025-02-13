rule Ransom_Win64_ForeigCrypt_PA_2147781680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ForeigCrypt.PA!MTB"
        threat_id = "2147781680"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ForeigCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Go build ID: \"juLDtqZciqqlSfnu77oh/6_EPf8zvlj1mHNu" ascii //weight: 5
        $x_1_2 = "hijackedhttp" ascii //weight: 1
        $x_1_3 = ".encrypted" ascii //weight: 1
        $x_1_4 = "fuckyoumalwarebytes" ascii //weight: 1
        $x_1_5 = "unreachableuserenv.dll" ascii //weight: 1
        $x_1_6 = "Inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

