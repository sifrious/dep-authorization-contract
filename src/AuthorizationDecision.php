<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

use InvalidArgumentException;
use JsonSerializable;
use Sifrious\ReferenceContract\CrossPackageReference;

final readonly class AuthorizationDecision implements JsonSerializable
{
    public const CONTRACT = 'sifrious.authorization-decision';
    public const CONTRACT_VERSION = 1;
    private function __construct(public bool $permitted, public string $code, public DisclosureMode $disclosure, public ?string $policyVersion = null, public ?CrossPackageReference $provenance = null)
    {
        if (preg_match('/^[a-z][a-z0-9._-]*$/', $code) !== 1) { throw new InvalidArgumentException('Authorization decision codes must be stable lowercase identifiers.'); }
    }
    public static function permit(string $code = 'permitted', ?string $policyVersion = null, ?CrossPackageReference $provenance = null): self { return new self(true, $code, DisclosureMode::ExplicitForbidden, $policyVersion, $provenance); }
    public static function deny(string $code, DisclosureMode $disclosure = DisclosureMode::ConcealAsMissing, ?string $policyVersion = null, ?CrossPackageReference $provenance = null): self { return new self(false, $code, $disclosure, $policyVersion, $provenance); }
    /** @return array<string,mixed> */
    public function toArray(): array { return ['contract'=>self::CONTRACT,'contract_version'=>self::CONTRACT_VERSION,'permitted'=>$this->permitted,'code'=>$this->code,'disclosure'=>$this->disclosure->value,'policy_version'=>$this->policyVersion,'provenance'=>$this->provenance?->toArray()]; }

    /** @param array<string,mixed> $value */
    public static function fromArray(array $value): self
    {
        if (($value['contract'] ?? null) !== self::CONTRACT || ($value['contract_version'] ?? null) !== self::CONTRACT_VERSION) {
            throw new InvalidArgumentException('Unsupported authorization decision contract.');
        }

        $permitted = $value['permitted'] ?? null;
        $code = $value['code'] ?? null;
        $disclosure = $value['disclosure'] ?? null;
        $policyVersion = $value['policy_version'] ?? null;
        $provenance = $value['provenance'] ?? null;

        if (! is_bool($permitted) || ! is_string($code) || ! is_string($disclosure) || DisclosureMode::tryFrom($disclosure) === null) {
            throw new InvalidArgumentException('Authorization decisions require permitted, code, and disclosure values.');
        }
        if ($policyVersion !== null && ! is_string($policyVersion)) {
            throw new InvalidArgumentException('Authorization decision policy version must be a string or null.');
        }
        if ($provenance !== null && ! is_array($provenance)) {
            throw new InvalidArgumentException('Authorization decision provenance must be a cross-package reference or null.');
        }

        return new self(
            $permitted,
            $code,
            DisclosureMode::from($disclosure),
            $policyVersion,
            $provenance === null ? null : CrossPackageReference::fromArray($provenance),
        );
    }

    /** @return array<string,mixed> */
    public function jsonSerialize(): array { return $this->toArray(); }
}
