using System.Runtime.InteropServices;

namespace TswapCli;

/// <summary>The real signal registration of <see cref="FilledFilesEnvironment.RegisterSignals"/>.</summary>
internal static class RunSignals
{
    public static IDisposable Register(Action<int> handler)
    {
        List<PosixSignalRegistration> registrations = [];
        void Add(PosixSignal signal, int number) =>
            registrations.Add(PosixSignalRegistration.Create(signal, context =>
            {
                context.Cancel = true; // tswap stays to clean up once the child has exited
                handler(number);
            }));
        Add(PosixSignal.SIGINT, 2);
        Add(PosixSignal.SIGTERM, 15);
        Add(PosixSignal.SIGHUP, 1);
        if (OperatingSystem.IsWindows())
            Add(PosixSignal.SIGQUIT, 3); // Ctrl+Break
        return new Registrations(registrations);
    }

    private sealed class Registrations(List<PosixSignalRegistration> registrations) : IDisposable
    {
        public void Dispose()
        {
            foreach (var registration in registrations)
                registration.Dispose();
        }
    }
}
