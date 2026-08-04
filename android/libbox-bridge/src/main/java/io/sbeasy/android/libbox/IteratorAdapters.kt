package io.sbeasy.android.libbox

import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface

internal class StringArray(values: Collection<String>) : StringIterator {
    private val items = values.toList()
    private var index = 0

    override fun len(): Int = items.size - index

    override fun hasNext(): Boolean = index < items.size

    override fun next(): String = items[index++]
}

internal class InterfaceArray(
    values: Collection<LibboxNetworkInterface>,
) : NetworkInterfaceIterator {
    private val iterator = values.iterator()

    override fun hasNext(): Boolean = iterator.hasNext()

    override fun next(): LibboxNetworkInterface = iterator.next()
}
