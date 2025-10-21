# Darkstore Package Example

This directory contains an example demonstrating how to use the `darkstore` package.

## Running the Example

From the project root directory:

```bash
make example
```

Or directly with Go:

```bash
go run example/main.go
```

## What the Example Demonstrates

1. **Creating a Store**: Shows how to create a new darkstore store
2. **Saving Secrets**: Demonstrates saving sensitive data at various paths
3. **Loading Secrets**: Shows how to retrieve stored secrets
4. **Key Rotation**: Shows the key rotation process and its effects
5. **Secure Memory Wiping**: Shows how to securely clear sensitive data from memory

## Security Notes

- The example uses a hardcoded key for demonstration purposes
- Always use `Wipe()` to clear sensitive data from memory when no longer needed
- Never store sensitive data in Go strings - always use byte slices.
