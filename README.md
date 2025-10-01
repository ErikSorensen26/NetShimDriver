<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NetShimDriver</title>
</head>
<body>

  <h1>NetShimDriver</h1>

  <p><strong>NetShimDriver</strong> is a Linux kernel module that creates <em>shim</em> network interfaces.<br>
  A shim device acts as a transparent layer over a backing NIC (physical or virtual).<br>
  Packets sent to the shim are forwarded to the real device, enabling interception, redirection, and experimentation at the kernel level.</p>

  <hr>

  <h2>✨ Features</h2>
  <ul>
    <li><strong>Transparent forwarding</strong> – Shim interfaces redirect packets to a bound real NIC.</li>
    <li><strong>Sysfs control</strong> – Simple binding via <code>/sys/class/net/&lt;shim&gt;/realdev</code>.</li>
    <li><strong>Multiple backends</strong> – Works with <code>eth</code>, <code>dummy</code>, <code>veth</code>, tap, and other NIC types.</li>
    <li><strong>Lightweight</strong> – Minimal overhead, reuses kernel SKB and <code>net_device</code> structures.</li>
    <li><strong>Extensible</strong> – Add filtering, logging, or modification in <code>start_xmit()</code>.</li>
  </ul>

  <hr>

  <h2>📦 Building</h2>

  <h3>Prerequisites</h3>
  <ul>
    <li>Linux kernel headers for your running kernel (<code>linux-headers-$(uname -r)</code> on Debian/Ubuntu, <code>kernel-devel</code> on Fedora/CentOS).</li>
    <li><code>make</code> and <code>gcc</code>.</li>
    <li>Root privileges.</li>
  </ul>

  <h3>Build</h3>
  <pre><code>make
</code></pre>

  <p>This produces the module:</p>
  <pre><code>netshimdriver.ko
</code></pre>

  <hr>

  <h2>🚀 Usage</h2>

  <h3>1. Load the module</h3>
  <pre><code>sudo insmod netshimdriver.ko
</code></pre>

  <p>Check:</p>
  <pre><code>lsmod | grep netshimdriver
dmesg | tail
</code></pre>

  <h3>2. Create a shim interface</h3>
  <pre><code>sudo ip link add shim0 type netshim
</code></pre>

  <h3>3. Bind it to a real device</h3>
  <pre><code>echo eth0 | sudo tee /sys/class/net/shim0/realdev
</code></pre>

  <p>Now <code>shim0</code> forwards packets to <code>eth0</code>.</p>

  <h3>4. Bring it up and configure</h3>
  <pre><code>sudo ip addr add 192.168.1.100/24 dev shim0
sudo ip link set shim0 up
</code></pre>

  <p>Test it:</p>
  <pre><code>ping -I shim0 192.168.1.1
</code></pre>

  <h3>5. Remove the shim</h3>
  <pre><code>sudo ip link del shim0
</code></pre>

  <h3>6. Unload the module</h3>
  <pre><code>sudo rmmod netshimdriver
</code></pre>

  <hr>

  <h2>📊 Example Workflow</h2>
  <pre><code># Load driver
sudo insmod netshimdriver.ko

# Create shim interface
sudo ip link add shim0 type netshim

# Bind shim0 to eth0
echo eth0 | sudo tee /sys/class/net/shim0/realdev

# Configure shim0
sudo ip addr add 10.0.0.2/24 dev shim0
sudo ip link set shim0 up

# Test traffic
ping -I shim0 10.0.0.1

# Cleanup
sudo ip link del shim0
sudo rmmod netshimdriver
</code></pre>

  <hr>

  <h2>📜 License</h2>
  <p>NetShimDriver is licensed under the <strong>GNU General Public License v2 (GPL-2.0)</strong>,  
  the same license as the Linux kernel.</p>

  <pre><code>NetShimDriver - A Linux kernel shim network interface driver
Copyright (C) 2025 Erik Sorensen
</code></pre>

</body>
</html>

