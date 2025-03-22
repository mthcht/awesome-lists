rule TrojanSpy_MSIL_Banker_D_2147647148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.D"
        threat_id = "2147647148"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "We are sorry but we cannot continue with your request because you have entered one or more details incorrectly." wide //weight: 2
        $x_5_2 = "MicrosoftWord.formCapitalone.resources" ascii //weight: 5
        $x_2_3 = "FormLLOYDS_Load" ascii //weight: 2
        $x_3_4 = "set_formBarclays" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Banker_I_2147656527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.I"
        threat_id = "2147656527"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "mainsender@gmail.com" wide //weight: 50
        $x_50_2 = "yesgame2005@hotmail.co.uk" wide //weight: 50
        $x_10_3 = "backupsender1@gmail.com" wide //weight: 10
        $x_10_4 = {66 6f 72 6d 43 61 70 69 74 61 6c 6f 6e 65 00 43 61 72 64 64 65 74 61 69 6c 73}  //weight: 10, accuracy: High
        $x_5_5 = "FormBarclaycard_Load" ascii //weight: 5
        $x_5_6 = "BankOfScot_Load" ascii //weight: 5
        $x_5_7 = "get_IntelligentFinanceMemo" ascii //weight: 5
        $x_5_8 = "m_Carddetails" ascii //weight: 5
        $x_5_9 = "zqrxzxkbivsioolr" wide //weight: 5
        $x_5_10 = "personal/logon/login.jsp" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 6 of ($x_5_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Banker_J_2147658255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.J"
        threat_id = "2147658255"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "need to register your memorable information" wide //weight: 3
        $x_3_2 = "txtatmpin" wide //weight: 3
        $x_1_3 = "AllianceMemo.resources" ascii //weight: 1
        $x_1_4 = "FormCardDetails2.resources" ascii //weight: 1
        $x_1_5 = "SanMemo.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Banker_L_2147686945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.L"
        threat_id = "2147686945"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 6f ?? ?? ?? ?? 13 06 11 06 73 ?? ?? ?? ?? 13 05 11 05 6f ?? ?? ?? ?? 0d 09 72 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 16 fe 01 7e ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 16 fe 01 5f 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "upload_arquivos/s.php" wide //weight: 1
        $x_1_3 = "[By N1gh7w0lf]" wide //weight: 1
        $x_1_4 = {61 00 76 00 73 00 69 00 6d 00 [0-4] 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Banker_M_2147689982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.M"
        threat_id = "2147689982"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 46 69 6c 65 5a 69 6c 6c 61 52 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {5f 70 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 63 72 69 70 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 70 61 73 74 61 5f 72 6f 61 6d 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 6e 64 65 72 65 63 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = "g0lp3l04rd3" wide //weight: 1
        $x_1_7 = {40 00 6e 00 6f 00 6d 00 65 00 70 00 63 00 [0-6] 40 00 4c 00 6f 00 67 00 69 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_Banker_N_2147692458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.N"
        threat_id = "2147692458"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "proteger seu computador de programas maliciosos" ascii //weight: 1
        $x_1_2 = "que podem ter acesso a seus dados confidenciais" ascii //weight: 1
        $x_1_3 = "Banco Bradesco S/A" ascii //weight: 1
        $x_1_4 = "vermelhabloqdata" wide //weight: 1
        $x_1_5 = "amarelabloqdata" wide //weight: 1
        $x_1_6 = "laranjabloqdata" wide //weight: 1
        $x_1_7 = "santabloqdata" wide //weight: 1
        $x_1_8 = "verdebloqdata" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Banker_N_2147692458_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.N"
        threat_id = "2147692458"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\GbPlugin\\" wide //weight: 1
        $x_1_2 = "dbo.infect" wide //weight: 1
        $x_1_3 = "@nomepc" wide //weight: 1
        $x_1_4 = "@senhas" wide //weight: 1
        $x_1_5 = "INTERNETBANKINGCAIXA" wide //weight: 1
        $x_1_6 = "itau." wide //weight: 1
        $x_1_7 = "bancobrasil." wide //weight: 1
        $x_1_8 = "bradesco." wide //weight: 1
        $x_1_9 = "caixa." wide //weight: 1
        $x_1_10 = {2d 00 20 00 54 00 65 00 63 00 6c 00 61 00 [0-16] 45 00 66 00 65 00 74 00 75 00 61 00 64 00 61 00 21 00}  //weight: 1, accuracy: Low
        $x_1_11 = "vermelhabloqdata" wide //weight: 1
        $x_1_12 = "amarelabloqdata" wide //weight: 1
        $x_1_13 = "laranjabloqdata" wide //weight: 1
        $x_1_14 = "santabloqdata" wide //weight: 1
        $x_1_15 = "verdebloqdata" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule TrojanSpy_MSIL_Banker_N_2147692458_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.N"
        threat_id = "2147692458"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GbPlugin\\" wide //weight: 1
        $x_1_2 = "dbo.infect" wide //weight: 1
        $x_1_3 = "@nomepc" wide //weight: 1
        $x_1_4 = "@senhas" wide //weight: 1
        $x_1_5 = "INTERNETBANKINGCAIXA" wide //weight: 1
        $x_1_6 = "itau." wide //weight: 1
        $x_1_7 = "bancobrasil." wide //weight: 1
        $x_1_8 = "bradesco." wide //weight: 1
        $x_1_9 = "caixa." wide //weight: 1
        $x_1_10 = "Orcamento Segue em anexo!" wide //weight: 1
        $x_1_11 = "[- C.l.i.c.k  E.f.e.t.u.a.d.o! ]" wide //weight: 1
        $x_1_12 = "[- Pe.d.i.d.o  T.o.k.e.n  |  A.s.s  |  S.e.r.i.a.l E.f.e.t.u.a.d.a! ]" wide //weight: 1
        $x_1_13 = "dbo.loginsdaweb (Logins, Tipo, titulo," wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule TrojanSpy_MSIL_Banker_N_2147692458_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.N"
        threat_id = "2147692458"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@nomepc" wide //weight: 1
        $x_1_2 = "dbo.infect" wide //weight: 1
        $x_1_3 = "\\GbPlugin\\" wide //weight: 1
        $x_1_4 = "@senhas" wide //weight: 1
        $x_1_5 = "[- C.l.i.c.k  E.f.e.t.u.a.d.o! ]" wide //weight: 1
        $x_1_6 = "[ - P.C  B.l.o.q.u.e.a.d.o! ]" wide //weight: 1
        $x_1_7 = "[- Pe.d.i.d.o  T.o.k.e.n  |  A.s.s  |  S.e.r.i.a.l E.f.e.t.u.a.d.a! ]" wide //weight: 1
        $x_1_8 = "[- T.e.x.t.o  E.n.v.i.a.d.o! ]" wide //weight: 1
        $x_1_9 = "C.E.F |" wide //weight: 1
        $x_1_10 = "B.B |" wide //weight: 1
        $x_1_11 = "I.T.A |" wide //weight: 1
        $x_1_12 = "S.I.C.R.E.D |" wide //weight: 1
        $x_1_13 = "S.A.N.T.A |" wide //weight: 1
        $x_1_14 = "B.R.A.D.A |" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule TrojanSpy_MSIL_Banker_P_2147707677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.P"
        threat_id = "2147707677"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Data Source=dbsq0010.whservidor.com" wide //weight: 1
        $x_1_2 = "Password=doido1010" wide //weight: 1
        $x_1_3 = "User ID=escolainte19" wide //weight: 1
        $x_1_4 = "MARCOS\\Desktop\\PROJETO DIVIDIDO\\PRODUTOS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Banker_EAFR_2147936727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Banker.EAFR!MTB"
        threat_id = "2147936727"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {20 00 40 01 00 8d 53 00 00 01 0a 2b 09 03 06 16 07 6f a4 00 00 0a 02 06 16 06 8e 69 6f 9b 00 00 0a 25 0b 2d e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

