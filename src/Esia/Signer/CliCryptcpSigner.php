<?php

/**
 * Класс для консолькольной подписи запросов с помощью утилиты Cryptcp
 */

namespace Esia\Signer;

use Esia\Signer\Exceptions\CannotReadCertificateException;
use Esia\Signer\Exceptions\CannotReadPrivateKeyException;
use Esia\Signer\Exceptions\NoSuchCertificateFileException;
use Esia\Signer\Exceptions\NoSuchKeyFileException;
use Esia\Signer\Exceptions\NoSuchTmpDirException;
use Esia\Signer\Exceptions\SignFailException;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

class CliCryptcpSigner implements SignerInterface
{
    use LoggerAwareTrait;


    /**
     * Пусть до утилиты
     * @var
     */
    protected $toolPath;

    /**
     * Слепок сертификата
     * @var
     */
    protected $thumbprint;

    /**
     * Пин-код
     *
     * @var string
     */
    protected $pin;

    /**
     * CliCryptcpSigner constructor.
     * @param string $toolPath
     * @param string $certThumbprint
     * @param string $certPin
     * @param string $tmpPath
     */
    public function __construct(
        string $toolPath,
        string $thumbprint,
        ?string $pin,
        string $tmpPath
    ) {
        $this->toolPath = $toolPath;
        $this->thumbprint = $thumbprint;
        $this->pin = $pin;
        $this->tmpPath = $tmpPath;
        $this->logger = new NullLogger();
    }


    /**
     * @param string $message
     * @return string
     * @throws SignFailException
     */

    public function sign(string $message): string
    {
        $this->checkFilesExists();

        $messageFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        $signFile = $this->tmpPath . DIRECTORY_SEPARATOR . $this->getRandomString();
        file_put_contents($messageFile, $message);

        /**
         * Параметры команды для подписи
         */
        $commandParams = [
            '-sign',
            '-thumbprint ' . $this->thumbprint,
            '-nochain',
            '-der'
        ];

        if ($this->pin) {
            $commandParams[] = '-pin ' . $this->pin;
        }

        /**
         * Агрументы
         */
        $commangArgs = [
            escapeshellarg($messageFile),
            escapeshellarg($signFile)
        ];

        //echo '<pre>';
        //var_dump($this->toolPath . ' ' . implode(' ', $commandParams) . ' ' . implode(' ', $commangArgs));

        $this->run(
            $this->toolPath . ' ' . implode(' ', $commandParams) . ' ' . implode(' ', $commangArgs)
        );

        $signed = file_get_contents($signFile);
        if ($signed === false) {
            $message = sprintf('cannot read %s file', $signFile);
            $this->logger->error($message);
            throw new SignFailException($message);
        }
        $sign = $this->urlSafe(base64_encode($signed));

        unlink($signFile);
        unlink($messageFile);
        return $sign;
    }

    /**
     * @param $command
     * @return void
     * @throws SignFailException
     */
    private function run(string $command): void
    {
        $process = proc_open(
            $command,
            [
                ['pipe', 'w'], // stdout
                ['pipe', 'w'], // stderr
            ],
            $pipes
        );

        $result = stream_get_contents($pipes[0]);
        fclose($pipes[0]);

        $errors = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $code = proc_close($process);
        /*var_dump($code);
        die();*/
        if (0 !== $code || $result === false) {
            $errors = $errors ?: 'unknown';
            $this->logger->error('Sign fail');
            $this->logger->error('SSL error: ' . $errors);
            throw new SignFailException($errors);
        }
    }

    /**
     * Генерация рандомной уникальной строки
     *
     * @return string
     */
    protected function getRandomString(): string {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * Проверка директорий
     * @throws SignFailException
     */
    protected function checkFilesExists(): void {
        if (!file_exists($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not found');
        }
        if (!is_writable($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not writable');
        }
    }

    /**
     * Url safe for base64
     *
     * @param string $string
     * @return string
     */
    protected function urlSafe($string): string
    {
        return rtrim(strtr(trim($string), '+/', '-_'), '=');
    }
}
