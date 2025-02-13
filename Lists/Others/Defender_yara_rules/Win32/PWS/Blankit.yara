rule PWS_Win32_Blankit_A_2147690173_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Blankit.A"
        threat_id = "2147690173"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Blankit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BANCOBRADESCO|BANCOITAU|30HORAS|" wide //weight: 2
        $x_2_2 = "\\DADOS.txt" wide //weight: 2
        $x_1_3 = "o de senha efetivacao." ascii //weight: 1
        $x_1_4 = "[Ok] Solicita" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Blankit_B_2147690854_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Blankit.B"
        threat_id = "2147690854"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Blankit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "42414E434F425241444553434F7C42414E434F495441557C3330484F" wide //weight: 1
        $x_1_2 = "\\DADOSAZUL" wide //weight: 1
        $x_1_3 = "<|>INF<|>0<<|" wide //weight: 1
        $x_1_4 = "<|UploadFile|>" wide //weight: 1
        $x_1_5 = "<|REQUESTKEYBOARD|>" wide //weight: 1
        $x_1_6 = "<|Resposta|>Senha:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

