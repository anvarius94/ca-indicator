# build_store_images.ps1 - Собирает материалы карточки Chrome Web Store из
# скриншотов попапа: изображения 1280x560/800, промо-плитку 440x280 и большое
# рекламное изображение 1400x560.
#
# Запуск:  powershell -ExecutionPolicy Bypass -File build_store_images.ps1
#
# Только Windows: рисование текста требует System.Drawing и системных шрифтов,
# в Node без внешних зависимостей это не сделать. Файл сохранён с BOM —
# PowerShell 5.1 иначе читает кириллицу как ANSI и падает на разборе.
#
# Все холсты создаются в Format24bppRgb: магазин требует 24-битный PNG без
# альфа-канала, а стандартный Bitmap в .NET 32-битный с альфой.
#
# Исходники берутся из screenshots/, результат кладётся в store/.

Add-Type -AssemblyName System.Drawing

$root = $PSScriptRoot
$shots = Join-Path $root "screenshots"
$outDir = Join-Path $root "store"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Палитра взята из popup.css, чтобы карточка не спорила с самим расширением
$bg        = [System.Drawing.ColorTranslator]::FromHtml("#0a0e17")
$panel     = [System.Drawing.ColorTranslator]::FromHtml("#131a29")
$textMain  = [System.Drawing.ColorTranslator]::FromHtml("#f1f5f9")
$textSec   = [System.Drawing.ColorTranslator]::FromHtml("#94a3b8")
$green     = [System.Drawing.ColorTranslator]::FromHtml("#22c55e")
$amber     = [System.Drawing.ColorTranslator]::FromHtml("#f59e0b")
$red       = [System.Drawing.ColorTranslator]::FromHtml("#ef4444")
$blue      = [System.Drawing.ColorTranslator]::FromHtml("#38bdf8")

# Магазин требует 24-битный PNG без альфа-канала, поэтому холсты создаём
# сразу в Format24bppRgb, а не в стандартном 32-битном ARGB.
$FMT = [System.Drawing.Imaging.PixelFormat]::Format24bppRgb

function New-Canvas {
    param([int]$W, [int]$H)
    $bmp = New-Object System.Drawing.Bitmap $W, $H, $FMT
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.TextRenderingHint = 'ClearTypeGridFit'
    return @{ Bitmap = $bmp; Graphics = $g }
}

function Draw-Shot {
    param($G, [string]$File, [int]$X, [int]$MaxH, [int]$CanvasH)
    $src = [System.Drawing.Image]::FromFile((Join-Path $shots $File))
    $scale = $MaxH / $src.Height
    $dw = [int]($src.Width * $scale); $dh = [int]($src.Height * $scale)
    $dy = [int](($CanvasH - $dh) / 2)
    $shadow = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(110, 0, 0, 0))
    $G.FillRectangle($shadow, ($X + 8), ($dy + 10), $dw, $dh)
    $shadow.Dispose()
    $G.DrawImage($src, $X, $dy, $dw, $dh)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(46, 255, 255, 255)), 1
    $G.DrawRectangle($pen, $X, $dy, $dw, $dh)
    $pen.Dispose()
    $src.Dispose()
    return $dw
}

function New-Shot {
    param(
        [string]$ShotFile, [string]$Title, [string[]]$Lines,
        [System.Drawing.Color]$Accent, [string]$OutFile
    )
    $W = 1280; $H = 800
    $c = New-Canvas -W $W -H $H
    $bmp = $c.Bitmap; $g = $c.Graphics
    $g.Clear($bg)

    $glow = New-Object System.Drawing.Drawing2D.GraphicsPath
    $glow.AddEllipse(-120, 120, 760, 720)
    $pgb = New-Object System.Drawing.Drawing2D.PathGradientBrush $glow
    $pgb.CenterColor = [System.Drawing.Color]::FromArgb(38, $Accent.R, $Accent.G, $Accent.B)
    $pgb.SurroundColors = @([System.Drawing.Color]::FromArgb(0, $Accent.R, $Accent.G, $Accent.B))
    $g.FillPath($pgb, $glow)
    $pgb.Dispose(); $glow.Dispose()

    $dx = 90
    $dw = Draw-Shot -G $g -File $ShotFile -X $dx -MaxH 680 -CanvasH $H

    $tx = $dx + $dw + 70
    $tw = $W - $tx - 80

    $fTitle = New-Object System.Drawing.Font("Segoe UI Semibold", 34, [System.Drawing.FontStyle]::Bold)
    $fBody  = New-Object System.Drawing.Font("Segoe UI", 19)
    $bTitle = New-Object System.Drawing.SolidBrush $Accent
    $bBody  = New-Object System.Drawing.SolidBrush $textSec
    $fmt = New-Object System.Drawing.StringFormat

    $rectTitle = New-Object System.Drawing.RectangleF $tx, 200, $tw, 200
    $g.DrawString($Title, $fTitle, $bTitle, $rectTitle, $fmt)
    $y = 200 + $g.MeasureString($Title, $fTitle, $tw).Height + 28
    foreach ($line in $Lines) {
        $r = New-Object System.Drawing.RectangleF $tx, $y, $tw, 400
        $g.DrawString($line, $fBody, $bBody, $r, $fmt)
        $y += $g.MeasureString($line, $fBody, $tw).Height + 18
    }

    $fName = New-Object System.Drawing.Font("Segoe UI Semibold", 17, [System.Drawing.FontStyle]::Bold)
    $bName = New-Object System.Drawing.SolidBrush $blue
    $g.DrawString("CA Indicator", $fName, $bName, $tx, ($H - 110))
    $fName.Dispose(); $bName.Dispose()
    $fTitle.Dispose(); $fBody.Dispose(); $bTitle.Dispose(); $bBody.Dispose()

    $g.Dispose()
    $bmp.Save((Join-Path $outDir $OutFile), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "  $OutFile  1280x800  24-bit"
}

Write-Output "Скриншоты для магазина:"

New-Shot -ShotFile "public-ca.png" `
    -Title "Сертификат публичного центра" `
    -Lines @(
        "В сертификате есть подписи Certificate Transparency. Их выдают только публично доверенным центрам, поэтому локально установленный корень такой сертификат подделать не может.",
        "Цепочка достраивается до корня из Chrome Root Store, все подписи проверяются криптографически."
    ) -Accent $green -OutFile "screenshot-1-public.png"

New-Shot -ShotFile "not-trusted-cert.png" `
    -Title "Трафик перехватывают" `
    -Lines @(
        "Сайт открыт по обычному адресу, но сертификат ему выдал не публичный центр, а корень, установленный на этом компьютере.",
        "Браузер при этом показывает обычный замок и молчит: подмена для него законна, ведь корню доверяет сама система."
    ) -Accent $amber -OutFile "screenshot-2-intercepted.png"

New-Shot -ShotFile "invalid-cert.png" `
    -Title "Браузер забраковал сертификат" `
    -Lines @(
        "Сертификат просрочен, отозван, самоподписан или выдан не на этот домен.",
        "Расширение ничего не блокирует: сайт открывается как обычно, вы просто видите, чем именно он защищён."
    ) -Accent $red -OutFile "screenshot-3-invalid.png"

New-Shot -ShotFile "whitelisted.png" `
    -Title "Ваше исключение для домена" `
    -Lines @(
        "Свой сервер можно разрешить вручную. Доверие привязано к паре «домен + сертификат»: на других доменах он доверенным не считается.",
        "Если сертификат на этом домене подменят, предупреждение вернётся."
    ) -Accent $amber -OutFile "screenshot-4-whitelist.png"

# ---------- Промо-плитка 440x280 ----------
$c = New-Canvas -W 440 -H 280
$bmp = $c.Bitmap; $g = $c.Graphics
$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Rectangle 0, 0, 440, 280), $bg, $panel, 45.0)
$g.FillRectangle($grad, 0, 0, 440, 280)
$grad.Dispose()

$icon = [System.Drawing.Image]::FromFile((Join-Path $root "icons\icon-trusted-128.png"))
$g.DrawImage($icon, 28, 44, 84, 84)
$icon.Dispose()

$fT = New-Object System.Drawing.Font("Segoe UI Semibold", 25, [System.Drawing.FontStyle]::Bold)
$bT = New-Object System.Drawing.SolidBrush $textMain
$g.DrawString("CA Indicator", $fT, $bT, 126, 48)
$fT.Dispose(); $bT.Dispose()

$fS = New-Object System.Drawing.Font("Segoe UI", 12)
$bS = New-Object System.Drawing.SolidBrush $blue
$g.DrawString("Кто на самом деле подписал сайт", $fS, $bS, 128, 92)
$fS.Dispose(); $bS.Dispose()

$pen = New-Object System.Drawing.Pen $green, 3
$g.DrawLine($pen, 28, 140, 96, 140)
$pen.Dispose()

$fB = New-Object System.Drawing.Font("Segoe UI", 12.5)
$bB = New-Object System.Drawing.SolidBrush $textSec
$r = New-Object System.Drawing.RectangleF 28, 156, 384, 100
$g.DrawString("Публичный удостоверяющий центр — или корень, установленный на вашем компьютере. Ничего не блокирует.", $fB, $bB, $r)
$fB.Dispose(); $bB.Dispose()

$g.Dispose()
$bmp.Save((Join-Path $outDir "promo-440x280.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "Промо-плитка:"
Write-Output "  promo-440x280.png  440x280  24-bit"

# ---------- Большое рекламное изображение 1400x560 ----------
$W = 1400; $H = 560
$c = New-Canvas -W $W -H $H
$bmp = $c.Bitmap; $g = $c.Graphics

$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Rectangle 0, 0, $W, $H), $bg, $panel, 20.0)
$g.FillRectangle($grad, 0, 0, $W, $H)
$grad.Dispose()

# Два скриншота справа: зелёный вердикт и перехват — контраст читается сразу
$null = Draw-Shot -G $g -File "public-ca.png" -X 760 -MaxH 470 -CanvasH $H
$null = Draw-Shot -G $g -File "not-trusted-cert.png" -X 1050 -MaxH 470 -CanvasH $H

$icon = [System.Drawing.Image]::FromFile((Join-Path $root "icons\icon-trusted-128.png"))
$g.DrawImage($icon, 70, 96, 76, 76)
$icon.Dispose()

$fT = New-Object System.Drawing.Font("Segoe UI Semibold", 42, [System.Drawing.FontStyle]::Bold)
$bT = New-Object System.Drawing.SolidBrush $textMain
$g.DrawString("CA Indicator", $fT, $bT, 162, 100)
$fT.Dispose(); $bT.Dispose()

$fS = New-Object System.Drawing.Font("Segoe UI Semibold", 21, [System.Drawing.FontStyle]::Bold)
$bS = New-Object System.Drawing.SolidBrush $blue
$g.DrawString("Кто на самом деле подписал сайт", $fS, $bS, 165, 158)
$fS.Dispose(); $bS.Dispose()

$pen = New-Object System.Drawing.Pen $green, 4
$g.DrawLine($pen, 70, 220, 150, 220)
$pen.Dispose()

$fB = New-Object System.Drawing.Font("Segoe UI", 18)
$bB = New-Object System.Drawing.SolidBrush $textSec
$r = New-Object System.Drawing.RectangleF 70, 248, 620, 220
$g.DrawString("Замок в адресной строке не означает, что вас никто не читает. Расширение показывает, защищён сайт глобально доверенным центром — или корнем, установленным на вашем компьютере.`n`nНичего не блокирует: всеми сайтами вы пользуетесь как раньше.", $fB, $bB, $r)
$fB.Dispose(); $bB.Dispose()

$g.Dispose()
$bmp.Save((Join-Path $outDir "marquee-1400x560.png"), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "Большое рекламное изображение:"
Write-Output "  marquee-1400x560.png  1400x560  24-bit"

# Старые имена скриншотов сменились — убираем, чтобы не путались
foreach ($old in @("screenshot-2-invalid.png", "screenshot-3-whitelist.png")) {
    $p = Join-Path $outDir $old
    if (Test-Path $p) { Remove-Item $p; Write-Output "Удалён устаревший файл: $old" }
}
