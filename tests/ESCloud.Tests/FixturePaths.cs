namespace ESCloud.Tests;

public static class FixturePaths
{
    public static string Find(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "fixtures", name);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not find fixtures/" + name + ".");
    }
}
