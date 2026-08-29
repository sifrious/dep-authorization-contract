<?php
declare(strict_types=1);
namespace Sifrious\AuthorizationContract;

use InvalidArgumentException;
use JsonSerializable;
use Sifrious\ReferenceContract\CrossPackageReference;

final readonly class TenantScope implements JsonSerializable
{
    public const CONTRACT = 'sifrious.tenant-scope';
    public const CONTRACT_VERSION = 1;
    private function __construct(public string $kind, public ?CrossPackageReference $tenant)
    {
        if (preg_match('/^[a-z][a-z0-9._-]*$/', $kind) !== 1) { throw new InvalidArgumentException('Tenant scope kinds must be stable lowercase identifiers.'); }
        if (($kind === 'unscoped') !== ($tenant === null)) { throw new InvalidArgumentException('Only an explicit unscoped scope may omit a tenant reference.'); }
    }
    public static function forTenant(string $kind, CrossPackageReference $tenant): self { return new self($kind, $tenant); }
    public static function unscoped(): self { return new self('unscoped', null); }
    public function equals(self $other): bool { return $this->toArray() === $other->toArray(); }
    /** @return array<string,mixed> */
    public function toArray(): array { return ['contract'=>self::CONTRACT,'contract_version'=>self::CONTRACT_VERSION,'kind'=>$this->kind,'tenant'=>$this->tenant?->toArray()]; }
    /** @param array<string,mixed> $value */
    public static function fromArray(array $value): self
    {
        if (($value['contract'] ?? null) !== self::CONTRACT || ($value['contract_version'] ?? null) !== self::CONTRACT_VERSION || ! is_string($value['kind'] ?? null)) { throw new InvalidArgumentException('Unsupported tenant scope contract.'); }
        $tenant = $value['tenant'] ?? null;
        if ($tenant !== null && ! is_array($tenant)) { throw new InvalidArgumentException('Tenant must be a cross-package reference or null.'); }
        return new self($value['kind'], $tenant === null ? null : CrossPackageReference::fromArray($tenant));
    }
    /** @return array<string,mixed> */
    public function jsonSerialize(): array { return $this->toArray(); }
}
